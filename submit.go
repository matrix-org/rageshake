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
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"github.com/ua-parser/uap-go/uaparser"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/google/go-github/github"
	"github.com/jordan-wright/email"
	"github.com/xanzy/go-gitlab"
)

var maxPayloadSize = 1024 * 1024 * 55 // 55 MB

type submitServer struct {
	// Template for building github and gitlab issues
	issueTemplate *template.Template

	// Template for building emails
	emailTemplate *template.Template

	// github client for reporting bugs. may be nil, in which case,
	// reporting is disabled.
	ghClient *github.Client
	glClient *gitlab.Client

	// External URI to /api
	apiPrefix string

	slack *slackClient

	genericWebhookClient *http.Client
	allowedAppNameMap    map[string]bool
	cfg                  *config
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

// `issueBodyTemplatePayload` contains the data made available to the `issue_body_template` and
// `email_body_template`.
//
// !!! Keep in step with the documentation in `templates/README.md` !!!
type issueBodyTemplatePayload struct {
	payload
	// Complete link to the listing URL that contains all uploaded logs
	ListingURL string
}

// `genericWebhookPayload` contains the data sent to webhooks configured with `generic_webhook_urls`, as
// well as being written to `details.json` in the rageshake directory.
//
// See `docs/generic_webhook.md`.
type genericWebhookPayload struct {
	payload
	// If a github/gitlab report is generated, this is set.
	ReportURL string `json:"report_url"`
	// Complete link to the listing URL that contains all uploaded logs
	ListingURL string `json:"listing_url"`
}

// `payload` stores information about a request made to this server.
//
// !!! Since this is inherited by `issueBodyTemplatePayload`, remember to keep it in step
// with the documentation in `templates/README.md` !!!
type payload struct {
	// A unique ID for this payload, generated within this server
	ID string `json:"id"`
	// A multi-line string containing the user description of the fault.
	UserText string `json:"user_text"`
	// A short slug to identify the app making the report
	AppName string `json:"app"`
	// Arbitrary data to annotate the report
	Data map[string]string `json:"data"`
	// Short labels to group reports
	Labels []string `json:"labels"`
	// A list of names of logs recognised by the server
	Logs []string `json:"logs"`
	// Set if there are log parsing errors
	LogErrors []string `json:"logErrors"`
	// A list of other files (not logs) uploaded as part of the rageshake
	Files []string `json:"files"`
	// Set if there are file parsing errors
	FileErrors []string `json:"fileErrors"`
	// The time the rageshake was submitted, in milliseconds since the epoch
	CreateTimeMillis int64 `json:"create_time"`
}

func (p payload) WriteTo(out io.Writer) {
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

type submitErrorResponse struct {
	Error     string `json:"error"`
	ErrorCode string `json:"errcode"`
	PolicyURL string `json:"policy_url,omitempty"`
}

func (s *submitServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// if we attempt to return a response without reading the request body,
	// apache gets upset and returns a 500. Let's try this.
	defer req.Body.Close()
	defer io.Copy(ioutil.Discard, req.Body)

	if req.Method != "POST" && req.Method != "OPTIONS" {
		writeError(w, 405, submitErrorResponse{Error: "Method not allowed. Use POST.", ErrorCode: ErrCodeMethodNotAllowed})
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
	s.handleSubmission(w, req)
}

func (s *submitServer) handleSubmission(w http.ResponseWriter, req *http.Request) {
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
		writeError(w, 500, submitErrorResponse{Error: "Internal error", ErrorCode: ErrCodeUnknown})
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

	// Filter out unwanted rageshakes, if a list is defined
	if len(s.allowedAppNameMap) != 0 && !s.allowedAppNameMap[p.AppName] {
		log.Printf("Blocking rageshake because app name %s not in list", p.AppName)
		if err := os.RemoveAll(reportDir); err != nil {
			log.Printf("Unable to remove report dir %s after rejected upload: %v\n",
				reportDir, err)
		}
		writeError(w, 400, submitErrorResponse{"This server does not accept rageshakes from your application.", ErrCodeDisallowedApp, "https://github.com/matrix-org/rageshake/blob/master/docs/blocked_rageshake.md"})
		return
	}
	rejection, code := s.cfg.matchesRejectionCondition(p)
	if rejection != nil {
		log.Printf("Blocking rageshake from app %s because it matches a rejection_condition: %s", p.AppName, *rejection)
		if err := os.RemoveAll(reportDir); err != nil {
			log.Printf("Unable to remove report dir %s after rejected upload: %v\n",
				reportDir, err)
		}
		userErrorText := fmt.Sprintf("This server did not accept the rageshake because it matches a rejection condition: %s.", *rejection)
		writeError(w, 400, submitErrorResponse{userErrorText, *code, "https://github.com/matrix-org/rageshake/blob/master/docs/blocked_rageshake.md"})
		return
	}

	// We use this prefix (eg, 2022-05-01/125223-abcde) as a unique identifier for this rageshake.
	// This is going to be used to uniquely identify rageshakes, even if they are not submitted to
	// an issue tracker for instance with automatic rageshakes that can be plentiful
	p.ID = prefix

	p.CreateTimeMillis = t.Unix() * 1e3 // TODO: drop support for Go 1.16, use UnixMilli

	resp, err := s.saveReport(req.Context(), *p, reportDir, listingURL)
	if err != nil {
		log.Println("Error handling report submission:", err)
		writeError(w, 500, submitErrorResponse{Error: "Could not save report", ErrorCode: ErrCodeUnknown})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(resp)
}

func writeError(w http.ResponseWriter, status int, response submitErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}

// parseRequest attempts to parse a received request as a bug report. If
// the request cannot be parsed, it responds with an error and returns nil.
func parseRequest(w http.ResponseWriter, req *http.Request, reportDir string) *payload {
	length, err := strconv.Atoi(req.Header.Get("Content-Length"))
	if err != nil {
		log.Println("Couldn't parse content-length", err)
		writeError(w, 400, submitErrorResponse{Error: "Bad Content-Length header", ErrorCode: ErrCodeBadHeader})
		return nil
	}
	if length > maxPayloadSize {
		log.Println("Content-length", length, "too large")
		writeError(w, 413, submitErrorResponse{Error: "Content too large", ErrorCode: ErrCodeContentTooLarge})
		return nil
	}

	contentType := req.Header.Get("Content-Type")
	if contentType != "" {
		d, _, _ := mime.ParseMediaType(contentType)
		if d == "multipart/form-data" {
			p, err1 := parseMultipartRequest(w, req, reportDir)
			if err1 != nil {
				log.Println("Error parsing multipart data:", err1)
				writeError(w, 400, submitErrorResponse{Error: "Bad multipart data", ErrorCode: ErrCodeBadContent})
				return nil
			}
			return p
		}
	}

	p, err := parseJSONRequest(w, req, reportDir)
	if err != nil {
		log.Println("Error parsing JSON body", err)
		writeError(w, 400, submitErrorResponse{Error: fmt.Sprintf("Could not decode payload: %s", err.Error()), ErrorCode: ErrCodeBadContent})
		return nil
	}

	return p
}

var uaParser *uaparser.Parser = uaparser.NewFromSaved()

func parseUserAgent(userAgent string) string {
	client := uaParser.Parse(userAgent)
	return fmt.Sprintf(`%s on %s running on %s device`, client.UserAgent.ToString(), client.Os.ToString(), client.Device.ToString())
}

func parseJSONRequest(w http.ResponseWriter, req *http.Request, reportDir string) (*payload, error) {
	var p jsonPayload
	if err := json.NewDecoder(req.Body).Decode(&p); err != nil {
		return nil, err
	}

	parsed := payload{
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

	parsed.AppName = p.AppName

	if p.UserAgent != "" {
		parsed.Data["Parsed-User-Agent"] = parseUserAgent(p.UserAgent)
		parsed.Data["User-Agent"] = p.UserAgent
	}
	if p.Version != "" {
		parsed.Data["Version"] = p.Version
	}

	return &parsed, nil
}

func parseMultipartRequest(w http.ResponseWriter, req *http.Request, reportDir string) (*payload, error) {
	rdr, err := req.MultipartReader()
	if err != nil {
		return nil, err
	}

	p := payload{
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

func parseFormPart(part *multipart.Part, p *payload, reportDir string) error {
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
func formPartToPayload(field, data string, p *payload) {
	if field == "text" {
		p.UserText = data
	} else if field == "app" {
		p.AppName = data
	} else if field == "version" {
		p.Data["Version"] = data
	} else if field == "user_agent" {
		p.Data["User-Agent"] = data
		p.Data["Parsed-User-Agent"] = parseUserAgent(data)
	} else if field == "label" {
		p.Labels = append(p.Labels, data)
	} else {
		p.Data[field] = data
	}
}

// we use a quite restrictive regexp for the filenames; in particular:
//
//   - a limited set of extensions. We are careful to limit the content-types
//     we will serve the files with, but somebody might accidentally point an
//     Apache or nginx at the upload directory, which would serve js files as
//     application/javascript and open XSS vulnerabilities. We also allow gzipped
//     text and json on the same basis (there's really no sense allowing gzipped images).
//
//   - no silly characters (/, ctrl chars, etc)
//
//   - nothing starting with '.'
var filenameRegexp = regexp.MustCompile(`^[a-zA-Z0-9_-]+\.(jpg|png|txt|json|txt\.gz|json\.gz)$`)

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
var logRegexp = regexp.MustCompile(`^[a-zA-Z0-9_-][a-zA-Z0-9_.-]*\.(log|txt)(\.gz)?$`)

// saveLogPart saves a log upload to the report directory.
//
// Returns the leafname of the saved file.
func saveLogPart(logNum int, filename string, reader io.Reader, reportDir string) (string, error) {
	// pick a name to save the log file with.
	//
	// some clients use sensible names (foo.N.log), which we preserve. For
	// others, we just make up a filename.
	//
	// We append a ".gz" extension if not already present, as the final file we store on
	// disk will be gzipped. The original filename may or may not contain a '.gz' depending
	// on the client that uploaded it, and if it was uploaded already compressed.

	var leafName string
	if logRegexp.MatchString(filename) {
		leafName = filename
		if !strings.HasSuffix(filename, ".gz") {
			leafName += ".gz"
		}
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

func (s *submitServer) saveReport(ctx context.Context, p payload, reportDir, listingURL string) (*submitResponse, error) {
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

	if err := s.sendEmail(p, reportDir, listingURL); err != nil {
		return nil, err
	}

	genericHookPayload := genericWebhookPayload{
		payload:    p,
		ReportURL:  resp.ReportURL,
		ListingURL: listingURL,
	}

	if err := s.submitGenericWebhook(genericHookPayload); err != nil {
		return nil, err
	}

	// finally, write the details to details.json
	if err := s.writeJSONDetailsFile(reportDir, genericHookPayload); err != nil {
		return nil, err
	}

	return &resp, nil
}

// `writeJSONDetailsFile` records all the details of the rageshake in `details.json` in the report directory.
func (s *submitServer) writeJSONDetailsFile(reportDir string, genericHookPayload genericWebhookPayload) error {
	f, err := os.Create(filepath.Join(reportDir, "details.json"))
	if err != nil {
		return err
	}
	defer f.Close()

	buffered := bufio.NewWriter(f)
	if err = json.NewEncoder(buffered).Encode(genericHookPayload); err != nil {
		return err
	}
	return buffered.Flush()
}

// submitGenericWebhook submits a basic JSON body to an endpoint configured in the config
//
// The request does not include the log body, only the metadata in the payload,
// with the required listingURL to obtain the logs over http if required.
//
// If a github or gitlab issue was previously made, the reportURL will also be passed.
//
// Uses a goroutine to handle the http request asynchronously as by this point all critical
// information has been stored.

func (s *submitServer) submitGenericWebhook(genericHookPayload genericWebhookPayload) error {
	if s.genericWebhookClient == nil {
		return nil
	}
	for _, url := range s.cfg.GenericWebhookURLs {
		// Enrich the payload with a reportURL and listingURL, to convert a single struct
		// to JSON easily

		payloadBuffer := new(bytes.Buffer)
		json.NewEncoder(payloadBuffer).Encode(genericHookPayload)
		req, err := http.NewRequest("POST", url, payloadBuffer)
		req.Header.Set("Content-Type", "application/json")
		if err != nil {
			log.Println("Unable to submit to URL ", url, " ", err)
			return err
		}
		log.Println("Making generic webhook request to URL ", url)
		go s.sendGenericWebhook(req)
	}
	return nil
}

func (s *submitServer) sendGenericWebhook(req *http.Request) {
	resp, err := s.genericWebhookClient.Do(req)
	if err != nil {
		log.Println("Unable to submit notification", err)
	} else {
		defer resp.Body.Close()
		log.Println("Got response", resp.Status)
	}
}

func (s *submitServer) submitGithubIssue(ctx context.Context, p payload, listingURL string, resp *submitResponse) error {
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

	issueReq, err := buildGithubIssueRequest(p, listingURL, s.issueTemplate)
	if err != nil {
		return err
	}

	issue, _, err := s.ghClient.Issues.Create(ctx, owner, repo, issueReq)
	if err != nil {
		return err
	}

	log.Println("Created issue:", *issue.HTMLURL)

	resp.ReportURL = *issue.HTMLURL

	return nil
}

func (s *submitServer) submitGitlabIssue(p payload, listingURL string, resp *submitResponse) error {
	if s.glClient == nil {
		return nil
	}

	glProj := s.cfg.GitlabProjectMappings[p.AppName]
	glLabels := s.cfg.GitlabProjectLabels[p.AppName]

	issueReq, err := buildGitlabIssueRequest(p, listingURL, s.issueTemplate, glLabels, s.cfg.GitlabIssueConfidential)
	if err != nil {
		return err
	}

	issue, _, err := s.glClient.Issues.CreateIssue(glProj, issueReq)

	if err != nil {
		return err
	}

	log.Println("Created issue:", issue.WebURL)

	resp.ReportURL = issue.WebURL

	return nil
}

func (s *submitServer) submitSlackNotification(p payload, listingURL string) error {
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

func buildReportTitle(p payload) string {
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

func buildGenericIssueRequest(p payload, listingURL string, bodyTemplate *template.Template) (title string, body []byte, err error) {
	var bodyBuf bytes.Buffer

	issuePayload := issueBodyTemplatePayload{
		payload:    p,
		ListingURL: listingURL,
	}

	if err = bodyTemplate.Execute(&bodyBuf, issuePayload); err != nil {
		return
	}

	title = buildReportTitle(p)
	body = bodyBuf.Bytes()

	return
}

func buildGithubIssueRequest(p payload, listingURL string, bodyTemplate *template.Template) (*github.IssueRequest, error) {
	title, body, err := buildGenericIssueRequest(p, listingURL, bodyTemplate)
	if err != nil {
		return nil, err
	}

	labels := p.Labels
	// go-github doesn't like nils
	if labels == nil {
		labels = []string{}
	}
	bodyStr := string(body)
	return &github.IssueRequest{
		Title:  &title,
		Body:   &bodyStr,
		Labels: &labels,
	}, nil
}

func buildGitlabIssueRequest(p payload, listingURL string, bodyTemplate *template.Template, labels []string, confidential bool) (*gitlab.CreateIssueOptions, error) {
	title, body, err := buildGenericIssueRequest(p, listingURL, bodyTemplate)
	if err != nil {
		return nil, err
	}

	if p.Labels != nil {
		labels = append(labels, p.Labels...)
	}

	bodyStr := string(body)
	return &gitlab.CreateIssueOptions{
		Title:        &title,
		Description:  &bodyStr,
		Confidential: &confidential,
		Labels:       labels,
	}, nil
}

func (s *submitServer) sendEmail(p payload, reportDir string, listingURL string) error {
	if len(s.cfg.EmailAddresses) == 0 {
		return nil
	}

	title, body, err := buildGenericIssueRequest(p, listingURL, s.emailTemplate)
	if err != nil {
		return err
	}

	e := email.NewEmail()

	e.From = "Rageshake <rageshake@matrix.org>"
	if s.cfg.EmailFrom != "" {
		e.From = s.cfg.EmailFrom
	}

	e.To = s.cfg.EmailAddresses
	e.Subject = fmt.Sprintf("[%s] %s", p.AppName, title)
	e.Text = body

	allFiles := append(p.Files, p.Logs...)
	for _, file := range allFiles {
		fullPath := filepath.Join(reportDir, file)
		e.AttachFile(fullPath)
	}

	var auth smtp.Auth = nil
	if s.cfg.SMTPPassword != "" || s.cfg.SMTPUsername != "" {
		host, _, _ := net.SplitHostPort(s.cfg.SMTPServer)
		auth = smtp.PlainAuth("", s.cfg.SMTPUsername, s.cfg.SMTPPassword, host)
	}
	err = e.Send(s.cfg.SMTPServer, auth)
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
