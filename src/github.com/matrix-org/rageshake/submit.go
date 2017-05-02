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
	"encoding/json"
	"fmt"
	"github.com/google/go-github/github"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var maxPayloadSize = 1024 * 1024 * 55 // 55 MB

type submitServer struct {
	// github client for reporting bugs. may be nil, in which case,
	// reporting is disabled.
	ghClient *github.Client

	// External URI to /api
	apiPrefix string

	// mappings from application to github owner/project
	githubProjectMappings map[string]string
}

type payload struct {
	Text      string            `json:"text"`
	AppName   string            `json:"app"`
	Version   string            `json:"version"`
	UserAgent string            `json:"user_agent"`
	Logs      []logEntry        `json:"logs"`
	Data      map[string]string `json:"data"`
	Labels    []string          `json:"labels"`
	Files     []string
}

type logEntry struct {
	ID    string `json:"id"`
	Lines string `json:"lines"`
}

type submitResponse struct {
	ReportURL string `json:"report_url,omitempty"`
}

func (s *submitServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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
		log.Println("Error handling report", err)
		http.Error(w, "Internal error", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(resp)
}

// parseRequest attempts to parse a received request as a bug report. If
// the request cannot be parsed, it responds with an error and returns nil.
func parseRequest(w http.ResponseWriter, req *http.Request, reportDir string) *payload {
	length, err := strconv.Atoi(req.Header.Get("Content-Length"))
	if err != nil {
		log.Println("Couldn't parse content-length", err)
		http.Error(w, "Bad content-length", 400)
		return nil
	}
	if length > maxPayloadSize {
		log.Println("Content-length", length, "too large")
		http.Error(w, fmt.Sprintf("Content too large (max %i)", maxPayloadSize), 413)
		return nil
	}

	contentType := req.Header.Get("Content-Type")
	if contentType != "" {
		d, _, _ := mime.ParseMediaType(contentType)
		if d == "multipart/form-data" {
			p, err1 := parseMultipartRequest(w, req, reportDir)
			if err1 != nil {
				log.Println("Error parsing multipart data", err1)
				http.Error(w, "Bad multipart data", 400)
				return nil
			}
			return p
		}
	}

	p, err := parseJSONRequest(w, req)
	if err != nil {
		log.Println("Error parsing JSON body", err)
		http.Error(w, fmt.Sprintf("Could not decode payload: %s", err.Error()), 400)
		return nil
	}
	return p
}

func parseJSONRequest(w http.ResponseWriter, req *http.Request) (*payload, error) {
	var p payload
	if err := json.NewDecoder(req.Body).Decode(&p); err != nil {
		return nil, err
	}

	p.Text = strings.TrimSpace(p.Text)

	if p.Data == nil {
		p.Data = make(map[string]string)
	}

	// backwards-compatibility hack: current versions of riot-android
	// don't set 'app', so we don't correctly file github issues.
	if p.AppName == "" && p.UserAgent == "Android" {
		p.AppName = "riot-android"

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
			p.Data[key] = val
		}
		p.Version = ""
	}

	return &p, nil
}

func parseMultipartRequest(w http.ResponseWriter, req *http.Request, reportDir string) (*payload, error) {
	rdr, err := req.MultipartReader()
	if err != nil {
		return nil, err
	}

	p := payload{
		Logs: make([]logEntry, 0),
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

	var partReader io.Reader
	if field == "compressed-log" {
		// decompress logs as we read them
		zrdr, err := gzip.NewReader(part)
		if err != nil {
			return err
		}
		defer zrdr.Close()
		partReader = zrdr
	} else {
		// read the field data directly from the multipart part
		partReader = part
	}

	if field == "file" {
		leafName, err := saveFormPart(part.FileName(), partReader, reportDir)
		if err != nil {
			return err
		}
		p.Files = append(p.Files, leafName)
		return nil
	}

	b, err := ioutil.ReadAll(partReader)
	if err != nil {
		return err
	}
	data := string(b)

	if field == "log" || field == "compressed-log" {
		// todo: we could save the log directly rather than pointlessly
		// unzipping and re-zipping.
		p.Logs = append(p.Logs, logEntry{
			ID:    part.FileName(),
			Lines: data,
		})
	} else {
		formPartToPayload(field, data, p)
	}
	return nil
}

// formPartToPayload updates the relevant part of *p from a name/value pair
// read from the form data.
func formPartToPayload(field, data string, p *payload) {
	if field == "text" {
		p.Text = data
	} else if field == "app" {
		p.AppName = data
	} else if field == "version" {
		p.Version = data
	} else if field == "user_agent" {
		p.UserAgent = data
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

func (s *submitServer) saveReport(ctx context.Context, p payload, reportDir, listingURL string) (*submitResponse, error) {
	resp := submitResponse{}

	var summaryBuf bytes.Buffer
	fmt.Fprintf(
		&summaryBuf,
		"%s\n\nNumber of logs: %d\nApplication: %s\nVersion: %s\nUser-Agent: %s\n",
		p.Text, len(p.Logs), p.AppName, p.Version, p.UserAgent,
	)
	fmt.Fprintf(&summaryBuf, "Labels: %s\n", strings.Join(p.Labels, ", "))
	for k, v := range p.Data {
		fmt.Fprintf(&summaryBuf, "%s: %s\n", k, v)
	}
	if err := gzipAndSave(summaryBuf.Bytes(), reportDir, "details.log.gz"); err != nil {
		return nil, err
	}

	for i, log := range p.Logs {
		if err := gzipAndSave([]byte(log.Lines), reportDir, fmt.Sprintf("logs-%04d.log.gz", i)); err != nil {
			return nil, err // TODO: Rollback?
		}
	}

	if s.ghClient == nil {
		// we're done here
		log.Println("GH issue submission disabled")
		return &resp, nil
	}

	// submit a github issue
	ghProj := s.githubProjectMappings[p.AppName]
	if ghProj == "" {
		log.Println("Not creating GH issue for unknown app", p.AppName)
		return &resp, nil
	}
	splits := strings.SplitN(ghProj, "/", 2)
	if len(splits) < 2 {
		log.Println("Can't create GH issue for invalid repo", ghProj)
	}
	owner, repo := splits[0], splits[1]

	issueReq := buildGithubIssueRequest(p, listingURL)

	issue, _, err := s.ghClient.Issues.Create(ctx, owner, repo, &issueReq)
	if err != nil {
		return nil, err
	}

	log.Println("Created issue:", *issue.HTMLURL)

	resp.ReportURL = *issue.HTMLURL

	return &resp, nil
}

func buildGithubIssueRequest(p payload, listingURL string) github.IssueRequest {
	var title string
	if p.Text == "" {
		title = "Untitled report"
	} else {
		// set the title to the first line of the user's report
		if i := strings.IndexAny(p.Text, "\r\n"); i < 0 {
			title = p.Text
		} else {
			title = p.Text[0:i]
		}
	}

	var bodyBuf bytes.Buffer
	fmt.Fprintf(&bodyBuf, "User message:\n```\n%s\n```\n", p.Text)
	for k, v := range p.Data {
		fmt.Fprintf(&bodyBuf, "%s: `%s`\n", k, v)
	}
	if p.Version != "" {
		fmt.Fprintf(&bodyBuf, "Version: `%s`\n", p.Version)
	}
	fmt.Fprintf(&bodyBuf, "[Logs](%s)", listingURL)

	for _, file := range p.Files {
		fmt.Fprintf(
			&bodyBuf,
			" / [%s](%s)",
			file,
			listingURL+"/"+file,
		)
	}

	body := bodyBuf.String()
	return github.IssueRequest{
		Title:  &title,
		Body:   &body,
		Labels: &p.Labels,
	}
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
