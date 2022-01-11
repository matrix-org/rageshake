/*
Copyright 2017 Vector Creations Ltd

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"mime"
	"mime/multipart"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/github"
	"github.com/jordan-wright/email"
	"github.com/xanzy/go-gitlab"
)

var maxPayloadSize = 1024 * 1024 * 55 // 55 MB

type submitServer struct {
	// github client for reporting bugs. may be nil, in which case,
	// reporting is disabled.
	ghClient *github.Client
	glClient *gitlab.Client

	// External URI to /api
	apiPrefix string

	slack *slackClient

	cfg *config
}

// the type of payload which can be uploaded as JSON to the submit endpoint
type jsonPayload struct {
	Text      string            `json:"text"`
	AppName   string            `json:"app"`
	Version   string            `json:"version"`
	UserAgent string            `json:"user_agent"`
	Logs      []jsonLogEntry    `json:"logs"`
	Data      map[string]string `json:"data"`
	Labels    []string          `json:"labels"`
}

type jsonLogEntry struct {
	ID    string `json:"id"`
	Lines string `json:"lines"`
}

// the payload after parsing
type parsedPayload struct {
	UserText   string
	AppName    string
	Data       map[string]string
	Labels     []string
	Logs       []string
	LogErrors  []string
	Files      []string
	FileErrors []string
}

func (p parsedPayload) WriteTo(out io.Writer) {
	fmt.Fprintf(
		out,
		"%s\n\nNumber of logs: %d\nApplication: %s\n",
		p.UserText, len(p.Logs), p.AppName,
	)
	fmt.Fprintf(out, "Labels: %s\n", strings.Join(p.Labels, ", "))

	var dataKeys []string
	for k := range p.Data {
		dataKeys = append(dataKeys, k)
	}
	sort.Strings(dataKeys)
	for _, k := range dataKeys {
		v := p.Data[k]
		fmt.Fprintf(out, "%s: %s\n", k, v)
	}
	if len(p.LogErrors) > 0 {
		fmt.Fprint(out, "Log upload failures:\n")
		for _, e := range p.LogErrors {
			fmt.Fprintf(out, "    %s\n", e)
		}
	}
	if len(p.FileErrors) > 0 {
		fmt.Fprint(out, "Attachment upload failures:\n")
		for _, e := range p.FileErrors {
			fmt.Fprintf(out, "    %s\n", e)
		}
	}
}

type submitResponse struct {
	ReportURL string `json:"report_url,omitempty"`
}

func (s *submitServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// if we attempt to return a response without reading the request body,
	// apache gets upset and returns a 500. Let's try this.
	defer req.Body.Close()
	defer io.Copy(ioutil.Discard, req.Body)

	if req.Method != "POST" && req.Method != "OPTIONS" {
		respond(405, w)
		return
	}

	// Set CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
	if req.Method == "OPTIONS" {
		respond(200, w)
		return
	}

	// create the report dir before parsing the request, so that we can dump
	// files straight in
	t := time.Now().UTC()
	prefix := t.Format("2006-01-02/150405")
	randBytes := make([]byte, 5)
	rand.Read(randBytes)
	prefix += "-" + base32.StdEncoding.EncodeToString(randBytes)
	reportDir := filepath.Join("bugs", prefix)
	if err := os.MkdirAll(reportDir, os.ModePerm); err != nil {
		log.Println("Unable to create report directory", err)
		http.Error(w, "Internal error", 500)
		return
	}

	listingURL := s.apiPrefix + "/listing/" + prefix
	log.Println("Handling report submission; listing URI will be", listingURL)

	p := parseRequest(w, req, reportDir)
	if p == nil {
		// parseRequest already wrote an error, but now let's delete the
		// useless report dir
		if err := os.RemoveAll(reportDir); err != nil {
			log.Printf("Unable to remove report dir %s after invalid upload: %v\n",
				reportDir, err)
		}
		return
	}

	resp, err := s.saveReport(req.Context(), *p, reportDir, listingURL)
	if err != nil {
		log.Println("Error handling report submission:", err)
		http.Error(w, "Internal error", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(resp)
}

// parseRequest attempts to parse a received request as a bug report. If
// the request cannot be parsed, it responds with an error and returns nil.
func parseRequest(w http.ResponseWriter, req *http.Request, reportDir string) *parsedPayload {
	length, err := strconv.Atoi(req.Header.Get("Content-Length"))
	if err != nil {
		log.Println("Couldn't parse content-length", err)
		http.Error(w, "Bad content-length", 400)
		return nil
	}
	if length > maxPayloadSize {
		log.Println("Content-length", length, "too large")
		http.Error(w, fmt.Sprintf("Content too large (max %d)", maxPayloadSize), 413)
		return nil
	}

	contentType := req.Header.Get("Content-Type")
	if contentType != "" {
		d, _, _ := mime.ParseMediaType(contentType)
		if d == "multipart/form-data" {
			p, err1 := parseMultipartRequest(w, req, reportDir)
			if err1 != nil {
				log.Println("Error parsing multipart data:", err1)
				http.Error(w, "Bad multipart data", 400)
				return nil
			}
			return p
		}
	}

	p, err := parseJSONRequest(w, req, reportDir)
	if err != nil {
		log.Println("Error parsing JSON body", err)
		http.Error(w, fmt.Sprintf("Could not decode payload: %s", err.Error()), 400)
		return nil
	}
	return p
}

func parseJSONRequest(w http.ResponseWriter, req *http.Request, reportDir string) (*parsedPayload, error) {
	var p jsonPayload
	if err := json.NewDecoder(req.Body).Decode(&p); err != nil {
		return nil, err
	}

	parsed := parsedPayload{
		UserText: strings.TrimSpace(p.Text),
		Data:     make(map[string]string),
		Labels:   p.Labels,
	}

	if p.Data != nil {
		parsed.Data = p.Data
	}

	for i, logfile := range p.Logs {
		buf := bytes.NewBufferString(logfile.Lines)
		leafName, err := saveLogPart(i, logfile.ID, buf, reportDir)
		if err != nil {
			log.Printf("Error saving log %s: %v", leafName, err)
			parsed.LogErrors = append(parsed.LogErrors, fmt.Sprintf("Error saving log %s: %v", leafName, err))
		} else {
			parsed.Logs = append(parsed.Logs, leafName)
		}
	}

	// backwards-compatibility hack: current versions of riot-android
	// don't set 'app', so we don't correctly file github issues.
	if p.AppName == "" && p.UserAgent == "Android" {
		parsed.AppName = "riot-android"

		// they also shove lots of stuff into 'Version' which we don't really
		// want in the github report
		for _, line := range strings.Split(p.Version, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			key := strings.TrimSpace(parts[0])
			val := ""
			if len(parts) > 1 {
				val = strings.TrimSpace(parts[1])
			}
			parsed.Data[key] = val
		}
	} else {
		parsed.AppName = p.AppName

		if p.UserAgent != "" {
			parsed.Data["User-Agent"] = p.UserAgent
		}
		if p.Version != "" {
			parsed.Data["Version"] = p.Version
		}
	}

	return &parsed, nil
}

func parseMultipartRequest(w http.ResponseWriter, req *http.Request, reportDir string) (*parsedPayload, error) {
	rdr, err := req.MultipartReader()
	if err != nil {
		return nil, err
	}

	p := parsedPayload{
		Data: make(map[string]string),
	}

	for true {
		part, err := rdr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		if err = parseFormPart(part, &p, reportDir); err != nil {
			return nil, err
		}
	}
	return &p, nil
}

func parseFormPart(part *multipart.Part, p *parsedPayload, reportDir string) error {
	defer part.Close()
	field := part.FormName()
	partName := part.FileName()

	var partReader io.Reader
	if field == "compressed-log" {
		// decompress logs as we read them.
		//
		// we could save the log directly rather than unzipping and re-zipping,
		// but doing so conveys the benefit of checking the validity of the
		// gzip at upload time.
		zrdr, err := gzip.NewReader(part)
		if err != nil {
			// we don't reject the whole request if there is an
			// error reading one attachment.
			log.Printf("Error unzipping %s: %v", partName, err)

			p.LogErrors = append(p.LogErrors, fmt.Sprintf("Error unzipping %s: %v", partName, err))
			return nil
		}
		defer zrdr.Close()
		partReader = zrdr
	} else {
		// read the field data directly from the multipart part
		partReader = part
	}

	if field == "file" {
		leafName, err := saveFormPart(partName, partReader, reportDir)
		if err != nil {
			log.Printf("Error saving %s %s: %v", field, partName, err)
			p.FileErrors = append(p.FileErrors, fmt.Sprintf("Error saving %s: %v", partName, err))
		} else {
			p.Files = append(p.Files, leafName)
		}
		return nil
	}

	if field == "log" || field == "compressed-log" {
		leafName, err := saveLogPart(len(p.Logs), partName, partReader, reportDir)
		if err != nil {
			log.Printf("Error saving %s %s: %v", field, partName, err)
			p.LogErrors = append(p.LogErrors, fmt.Sprintf("Error saving %s: %v", partName, err))
		} else {
			p.Logs = append(p.Logs, leafName)
		}
		return nil
	}

	b, err := ioutil.ReadAll(partReader)
	if err != nil {
		return err
	}
	data := string(b)
	formPartToPayload(field, data, p)
	return nil
}

// formPartToPayload updates the relevant part of *p from a name/value pair
// read from the form data.
func formPartToPayload(field, data string, p *parsedPayload) {
	if field == "text" {
		p.UserText = data
	} else if field == "app" {
		p.AppName = data
	} else if field == "version" {
		p.Data["Version"] = data
	} else if field == "user_agent" {
		p.Data["User-Agent"] = data
	} else if field == "label" {
		p.Labels = append(p.Labels, data)
	} else {
		p.Data[field] = data
	}
}

// we use a quite restrictive regexp for the filenames; in particular:
//
// * a limited set of extensions. We are careful to limit the content-types
//   we will serve the files with, but somebody might accidentally point an
//   Apache or nginx at the upload directory, which would serve js files as
//   application/javascript and open XSS vulnerabilities.
//
// * no silly characters (/, ctrl chars, etc)
//
// * nothing starting with '.'
var filenameRegexp = regexp.MustCompile(`^[a-zA-Z0-9_-]+\.(jpg|png|txt)$`)

// saveFormPart saves a file upload to the report directory.
//
// Returns the leafname of the saved file.
func saveFormPart(leafName string, reader io.Reader, reportDir string) (string, error) {
	if !filenameRegexp.MatchString(leafName) {
		return "", fmt.Errorf("Invalid upload filename")
	}

	fullName := filepath.Join(reportDir, leafName)

	log.Println("Saving uploaded file", leafName, "to", fullName)

	f, err := os.Create(fullName)
	if err != nil {
		return "", err
	}
	defer f.Close()

	_, err = io.Copy(f, reader)
	if err != nil {
		return "", err
	}

	return leafName, nil
}

// we require a sensible extension, and don't allow the filename to start with
// '.'
var logRegexp = regexp.MustCompile(`^[a-zA-Z0-9_-][a-zA-Z0-9_.-]*\.(log|txt)$`)

// saveLogPart saves a log upload to the report directory.
//
// Returns the leafname of the saved file.
func saveLogPart(logNum int, filename string, reader io.Reader, reportDir string) (string, error) {
	// pick a name to save the log file with.
	//
	// some clients use sensible names (foo.N.log), which we preserve. For
	// others, we just make up a filename.
	//
	// Either way, we need to append .gz, because we're compressing it.
	var leafName string
	if logRegexp.MatchString(filename) {
		leafName = filename + ".gz"
	} else {
		leafName = fmt.Sprintf("logs-%04d.log.gz", logNum)
	}

	fullname := filepath.Join(reportDir, leafName)

	f, err := os.Create(fullname)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()

	_, err = io.Copy(gz, reader)
	if err != nil {
		return "", err
	}

	return leafName, nil
}

func (s *submitServer) saveReport(ctx context.Context, p parsedPayload, reportDir, listingURL string) (*submitResponse, error) {
	var summaryBuf bytes.Buffer
	resp := submitResponse{}
	p.WriteTo(&summaryBuf)
	if err := gzipAndSave(summaryBuf.Bytes(), reportDir, "details.log.gz"); err != nil {
		return nil, err
	}

	if err := s.submitGithubIssue(ctx, p, listingURL, &resp); err != nil {
		return nil, err
	}

	if err := s.submitGitlabIssue(p, listingURL, &resp); err != nil {
		return nil, err
	}

	if err := s.submitSlackNotification(p, listingURL); err != nil {
		return nil, err
	}

	if err := s.sendEmail(p, reportDir); err != nil {
		return nil, err
	}

	return &resp, nil
}

func (s *submitServer) submitGithubIssue(ctx context.Context, p parsedPayload, listingURL string, resp *submitResponse) error {
	if s.ghClient == nil {
		return nil
	}

	// submit a github issue
	ghProj := s.cfg.GithubProjectMappings[p.AppName]
	if ghProj == "" {
		log.Println("Not creating GH issue for unknown app", p.AppName)
		return nil
	}
	splits := strings.SplitN(ghProj, "/", 2)
	if len(splits) < 2 {
		log.Println("Can't create GH issue for invalid repo", ghProj)
	}
	owner, repo := splits[0], splits[1]

	issueReq := buildGithubIssueRequest(p, listingURL)

	issue, _, err := s.ghClient.Issues.Create(ctx, owner, repo, &issueReq)
	if err != nil {
		return err
	}

	log.Println("Created issue:", *issue.HTMLURL)

	resp.ReportURL = *issue.HTMLURL

	return nil
}

func (s *submitServer) submitGitlabIssue(p parsedPayload, listingURL string, resp *submitResponse) error {
	if s.glClient == nil {
		return nil
	}

	glProj := s.cfg.GitlabProjectMappings[p.AppName]
	glLabels := s.cfg.GitlabProjectLabels[p.AppName]

	issueReq := buildGitlabIssueRequest(p, listingURL, glLabels, s.cfg.GitlabIssueConfidential)

	issue, _, err := s.glClient.Issues.CreateIssue(glProj, issueReq)

	if err != nil {
		return err
	}

	log.Println("Created issue:", issue.WebURL)

	resp.ReportURL = issue.WebURL

	return nil
}

func (s *submitServer) submitSlackNotification(p parsedPayload, listingURL string) error {
	if s.slack == nil {
		return nil
	}

	slackBuf := fmt.Sprintf(
		"%s\nApplication: %s\nReport: %s",
		p.UserText, p.AppName, listingURL,
	)

	err := s.slack.Notify(slackBuf)
	if err != nil {
		return err
	}

	return nil
}

func buildReportTitle(p parsedPayload) string {
	// set the title to the first (non-empty) line of the user's report, if any
	trimmedUserText := strings.TrimSpace(p.UserText)
	if trimmedUserText == "" {
		return "Untitled report"
	}

	if i := strings.IndexAny(trimmedUserText, "\r\n"); i >= 0 {
		return trimmedUserText[0:i]
	}

	return trimmedUserText
}

func buildReportBody(p parsedPayload, newline, quoteChar string) *bytes.Buffer {
	var bodyBuf bytes.Buffer
	fmt.Fprintf(&bodyBuf, "User message:\n\n%s\n\n", p.UserText)
	var dataKeys []string
	for k := range p.Data {
		dataKeys = append(dataKeys, k)
	}
	sort.Strings(dataKeys)
	for _, k := range dataKeys {
		v := p.Data[k]
		fmt.Fprintf(&bodyBuf, "%s: %s%s%s%s", k, quoteChar, v, quoteChar, newline)
	}

	return &bodyBuf
}

func buildGenericIssueRequest(p parsedPayload, listingURL string) (title, body string) {
	bodyBuf := buildReportBody(p, "  \n", "`")

	// Add log links to the body
	fmt.Fprintf(bodyBuf, "\n[Logs](%s)", listingURL)

	for _, file := range p.Files {
		fmt.Fprintf(
			bodyBuf,
			" / [%s](%s)",
			file,
			listingURL+"/"+file,
		)
	}

	title = buildReportTitle(p)

	body = bodyBuf.String()

	return
}

func buildGithubIssueRequest(p parsedPayload, listingURL string) github.IssueRequest {
	title, body := buildGenericIssueRequest(p, listingURL)

	labels := p.Labels
	// go-github doesn't like nils
	if labels == nil {
		labels = []string{}
	}
	return github.IssueRequest{
		Title:  &title,
		Body:   &body,
		Labels: &labels,
	}
}

func buildGitlabIssueRequest(p parsedPayload, listingURL string, labels []string, confidential bool) *gitlab.CreateIssueOptions {
	title, body := buildGenericIssueRequest(p, listingURL)

	if p.Labels != nil {
		labels = append(labels, p.Labels...)
	}

	return &gitlab.CreateIssueOptions{
		Title:        &title,
		Description:  &body,
		Confidential: &confidential,
		Labels:       labels,
	}
}

func (s *submitServer) sendEmail(p parsedPayload, reportDir string) error {
	if len(s.cfg.EmailAddresses) == 0 {
		return nil
	}

	e := email.NewEmail()

	e.From = "Rageshake <rageshake@matrix.org>"
	if s.cfg.EmailFrom != "" {
		e.From = s.cfg.EmailFrom
	}

	e.To = s.cfg.EmailAddresses

	e.Subject = fmt.Sprintf("[%s] %s", p.AppName, buildReportTitle(p))

	e.Text = buildReportBody(p, "\n", "\"").Bytes()

	allFiles := append(p.Files, p.Logs...)
	for _, file := range allFiles {
		fullPath := filepath.Join(reportDir, file)
		e.AttachFile(fullPath)
	}

	var auth smtp.Auth = nil
	if s.cfg.SMTPPassword != "" || s.cfg.SMTPUsername != "" {
		auth = smtp.PlainAuth("", s.cfg.SMTPUsername, s.cfg.SMTPPassword, s.cfg.SMTPServer)
	}
	err := e.Send(s.cfg.SMTPServer, auth)
	if err != nil {
		return err
	}

	return nil
}

func respond(code int, w http.ResponseWriter) {
	w.WriteHeader(code)
	w.Write([]byte("{}"))
}

func gzipAndSave(data []byte, dirname, fpath string) error {
	fpath = filepath.Join(dirname, fpath)

	if _, err := os.Stat(fpath); err == nil {
		return fmt.Errorf("file already exists") // the user can just retry
	}
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(data); err != nil {
		return err
	}
	if err := gz.Flush(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := ioutil.WriteFile(fpath, b.Bytes(), 0644); err != nil {
		return err
	}
	return nil
}
