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
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var maxPayloadSize = 1024 * 1024 * 55 // 55 MB

type submitServer struct {
	// External URI to /api
	apiPrefix string

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
	UserText   string            `json:"user_text"`
	AppName    string            `json:"app_name"`
	Data       map[string]string `json:"data"`
	Labels     []string          `json:"labels"`
	Logs       []string          `json:"log_files"`
	LogErrors  []string          `json:"log_file_errors"`
	Files      []string          `json:"files"`
	FileErrors []string          `json:"file_errors"`

	MatrixWhoami *matrixWhoamiResponse `json:"-"`
	IMAWhoami    *imaWhoamiResponse    `json:"-"`

	IsInternal bool `json:"-"`

	VerifiedUserID   string `json:"verified_user_id"`
	VerifiedDeviceID string `json:"verified_device_id"`
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
	ReportURL   string `json:"report_url,omitempty"`
	IssueNumber string `json:"issue_number,omitempty"`
}

var gplaySpamEmailRegex = regexp.MustCompile(`^[a-z]+.\d{5}@gmail\.com$`)

func (s *submitServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// if we attempt to return a response without reading the request body,
	// apache gets upset and returns a 500. Let's try this.
	defer req.Body.Close()
	defer io.Copy(io.Discard, req.Body)

	if req.Method != "POST" && req.Method != "OPTIONS" {
		respond(405, w)
		return
	}

	// Set CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
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

	p := s.parseRequest(w, req, reportDir)
	if p == nil {
		// parseRequest already wrote an error, but now let's delete the
		// useless report dir
		if err := os.RemoveAll(reportDir); err != nil {
			log.Printf("Unable to remove report dir %s after invalid upload: %v\n",
				reportDir, err)
		}
		return
	}

	if req.Context().Err() != nil {
		return
	}

	err := s.saveReport(*p, reportDir, listingURL)
	if err != nil {
		log.Println("Error handling report submission:", err)
		http.Error(w, "Internal error", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write([]byte("{}"))
}

type globalBridgeStateInfo struct {
	IsHungry bool `json:"isHungry"`
}

type whoamiBridgeState struct {
	StateEvent string                `json:"stateEvent"`
	Info       globalBridgeStateInfo `json:"info"`
	Reason     string                `json:"reason"`
	Source     string                `json:"source"`
	CreatedAt  time.Time             `json:"createdAt"`
}

//type whoamiRemoteState struct {
//	StateEvent string         `json:"state_event"`
//	Info       map[string]any `json:"info"`
//	Reason     string         `json:"reason"`
//	Timestamp  int64          `json:"timestamp"`
//	RemoteID   string         `json:"remote_id"`
//	RemoteName string         `json:"remote_name"`
//}

type whoamiBridgeInfo struct {
	//Version     string                       `json:"version"`
	//ConfigHash  string                       `json:"configHash"`
	BridgeState whoamiBridgeState `json:"bridgeState"`
	//RemoteState map[string]whoamiRemoteState `json:"remoteState"`
}

type matrixWhoamiResponse struct {
	UserInfo struct {
		Hungryserv    bool      `json:"useHungryserv"`
		Channel       string    `json:"channel"`
		SupportRoomID string    `json:"supportRoomId"`
		Email         string    `json:"email"`
		CreatedAt     time.Time `json:"createdAt"`
	}
	User struct {
		Bridges map[string]whoamiBridgeInfo `json:"bridges"`
	} `json:"user"`
	Matrix struct {
		UserID   string `json:"user_id"`
		DeviceID string `json:"device_id"`
	} `json:"matrix"`
}

type imaWhoamiResponse struct {
	IMAUserToken string `json:"ima_user_token"`
	AnalyticsID  string `json:"analytics_id"`
	Email        string `json:"email"`
	Subscription struct {
		ExpiresAt string `json:"expires_at"`
		Active    bool   `json:"active"`
	} `json:"subscription"`
}

func (s *submitServer) verifyIMAToken(ctx context.Context, auth, userID string) (*imaWhoamiResponse, error) {
	if len(auth) == 0 {
		return nil, fmt.Errorf("missing authorization header")
	} else if !strings.HasPrefix(auth, "Bearer ") {
		return nil, fmt.Errorf("invalid authorization header")
	}

	// The user ID in this case should be an email
	atIndex := strings.IndexRune(userID, '@')
	if atIndex <= 0 {
		return nil, fmt.Errorf("invalid user ID")
	}

	// All of iMessage on Android is on beeper.com
	apiServerURL, ok := s.cfg.APIServerURLs["beeper.com"]
	if !ok {
		return nil, fmt.Errorf("beeper.com server API server URL not configured")
	}

	baseURL, _ := url.Parse(apiServerURL)
	baseURL.Path = "/ima/whoami"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Authorization", auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make whoami request: %w", err)
	}
	defer resp.Body.Close()
	var respData imaWhoamiResponse
	if respBytes, err := io.ReadAll(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read whoami response body (status %d): %w", resp.StatusCode, err)
	} else if resp.StatusCode != 200 {
		return nil, fmt.Errorf("whoami returned non-200 status code %d (data: %s)", resp.StatusCode, respBytes)
	} else if err = json.Unmarshal(respBytes, &respData); err != nil {
		return nil, fmt.Errorf("failed to parse success whoami response body: %w", err)
	}
	return &respData, nil
}

func (s *submitServer) verifyMatrixAccessToken(ctx context.Context, auth, userID string) (*matrixWhoamiResponse, error) {
	if len(auth) == 0 {
		return nil, fmt.Errorf("missing authorization header")
	} else if !strings.HasPrefix(auth, "Bearer ") {
		return nil, fmt.Errorf("invalid authorization header")
	}

	colonIndex := strings.IndexRune(userID, ':')
	if colonIndex <= 0 || strings.IndexRune(userID, '@') != 0 {
		return nil, fmt.Errorf("invalid user ID")
	}

	server := userID[colonIndex+1:]
	apiServerURL, ok := s.cfg.APIServerURLs[server]
	if !ok {
		return nil, fmt.Errorf("unsupported homeserver '%s'", server)
	}

	baseURL, _ := url.Parse(apiServerURL)
	baseURL.Path = "/whoami"
	baseURL.RawQuery = url.Values{"includeMatrix": []string{"1"}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Authorization", auth)
	var respData matrixWhoamiResponse
	resp, err := http.DefaultClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to make whoami request: %w", err)
	} else if respBytes, err := io.ReadAll(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read whoami response body (status %d): %w", resp.StatusCode, err)
	} else if resp.StatusCode != 200 {
		return nil, fmt.Errorf("whoami returned non-200 status code %d (data: %s)", resp.StatusCode, respBytes)
	} else if err = json.Unmarshal(respBytes, &respData); err != nil {
		return nil, fmt.Errorf("failed to parse success whoami response body: %w", err)
	}
	return &respData, nil
}

func isMultipart(contentType string) bool {
	if len(contentType) == 0 {
		return false
	}
	d, _, _ := mime.ParseMediaType(contentType)
	return d == "multipart/form-data"
}

// parseRequest attempts to parse a received request as a bug report. If
// the request cannot be parsed, it responds with an error and returns nil.
func (s *submitServer) parseRequest(w http.ResponseWriter, req *http.Request, reportDir string) *parsedPayload {
	length, err := strconv.Atoi(req.Header.Get("Content-Length"))
	if err != nil {
		log.Println("Couldn't parse content-length", err)
		http.Error(w, "Bad content-length", http.StatusBadRequest)
		return nil
	}
	if length > maxPayloadSize {
		log.Println("Content-length", length, "too large")
		http.Error(w, fmt.Sprintf("Content too large (max %d)", maxPayloadSize), http.StatusRequestEntityTooLarge)
		return nil
	}

	var p *parsedPayload
	if isMultipart(req.Header.Get("Content-Type")) {
		p, err = parseMultipartRequest(w, req, reportDir)
		if err != nil {
			log.Println("Error parsing multipart data:", err)
			http.Error(w, "Bad multipart data", http.StatusBadRequest)
			return nil
		}
	} else {
		p, err = parseJSONRequest(w, req, reportDir)
		if err != nil {
			log.Println("Error parsing JSON body", err)
			http.Error(w, fmt.Sprintf("Could not decode payload: %s", err.Error()), http.StatusBadRequest)
			return nil
		}
	}

	userID, hasUserID := p.Data["user_id"]
	delete(p.Data, "user_id")
	delete(p.Data, "verified_device_id")
	if !hasUserID {
		return p
	} else if p.AppName == "booper" {
		if gplaySpamEmailRegex.MatchString(userID) {
			log.Println("Dropping report from", userID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("{}"))
			return nil
		}

		whoami, err := s.verifyIMAToken(req.Context(), req.Header.Get("Authorization"), userID)
		if err != nil {
			log.Printf("Error verifying user ID (%s): %v", userID, err)
			p.Data["unverified_user_id"] = userID
		} else {
			p.IMAWhoami = whoami
			p.VerifiedUserID = whoami.Email
			if p.VerifiedUserID != userID {
				log.Printf("Mismatching user ID (verified: %s, input: %s), overriding...", p.VerifiedUserID, userID)
			}
			p.Data["user_id"] = p.VerifiedUserID
		}
	} else {
		whoami, err := s.verifyMatrixAccessToken(req.Context(), req.Header.Get("Authorization"), userID)
		if err != nil {
			log.Printf("Error verifying user ID (%s): %v", userID, err)
			p.Data["unverified_user_id"] = userID
		} else {
			p.MatrixWhoami = whoami
			p.VerifiedUserID = whoami.Matrix.UserID
			p.VerifiedDeviceID = whoami.Matrix.DeviceID
			if p.VerifiedUserID != userID {
				log.Printf("Mismatching user ID (verified: %s, input: %s), overriding...", p.VerifiedUserID, userID)
			}
			p.Data["verified_device_id"] = p.VerifiedDeviceID
			p.Data["user_id"] = p.VerifiedUserID
		}
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

	b, err := io.ReadAll(partReader)
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
		if len(p.Data[field]) == 0 {
			p.Data[field] = data
		} else {
			p.Data[field] = fmt.Sprintf("%s, %s", p.Data[field], data)
		}
	} else {
		p.Data[field] = data
	}
}

// we use a quite restrictive regexp for the filenames; in particular:
//
//   - a limited set of extensions. We are careful to limit the content-types
//     we will serve the files with, but somebody might accidentally point an
//     Apache or nginx at the upload directory, which would serve js files as
//     application/javascript and open XSS vulnerabilities.
//
// * no silly characters (/, ctrl chars, etc)
//
// * nothing starting with '.'
var filenameRegexp = regexp.MustCompile(`^[a-zA-Z0-9_-]+\.(jpg|jpeg|png|heic|gif|mp4|txt|mov|heif|har|json)$`)

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

func (s *submitServer) saveReportBackground(p parsedPayload, reportDir, listingURL string) error {
	var resp submitResponse

	if err := s.submitLinearIssue(p, listingURL, &resp); err != nil {
		return err
	}

	if err := s.submitWebhook(context.Background(), p, listingURL, &resp); err != nil {
		return err
	}

	return nil
}

func (s *submitServer) saveReport(p parsedPayload, reportDir, listingURL string) error {
	var summaryBuf bytes.Buffer
	p.WriteTo(&summaryBuf)
	if err := gzipAndSave(summaryBuf.Bytes(), reportDir, "details.log.gz"); err != nil {
		return err
	}

	go func() {
		err := s.saveReportBackground(p, reportDir, listingURL)
		if err != nil {
			fmt.Println("Error submitting report in background:", err)
		}
	}()

	return nil
}

func (s *submitServer) submitLinearIssue(p parsedPayload, listingURL string, resp *submitResponse) error {
	if len(s.cfg.LinearToken) == 0 {
		return nil
	}

	teamID, ok := appToTeamID[p.AppName]
	if !ok {
		return nil
	}

	bridge := p.Data["bridge"]

	labelIDs := []string{labelRageshake}
	subscriberIDs := make([]string, 0)

	// Determine if the user has a Linear ID and add them to the subscriber
	// list if they do have an ID.
	var email string
	if p.MatrixWhoami != nil && p.MatrixWhoami.UserInfo.Email != "" {
		email = p.MatrixWhoami.UserInfo.Email
	} else if p.IMAWhoami != nil && p.IMAWhoami.Email != "" {
		email = p.IMAWhoami.Email
	}
	if email != "" {
		if linearID := getLinearID(email, s.cfg.LinearToken); linearID != "" {
			subscriberIDs = []string{linearID}
		}
	}

	if p.AppName == "booper" {
		labelIDs = append(labelIDs, labelBooperApp)
	}

	isInternal := len(subscriberIDs) > 0 || strings.HasSuffix(p.VerifiedUserID, ":beeper-dev.com") || strings.HasSuffix(p.VerifiedUserID, ":beeper-staging.com")
	if isInternal {
		p.IsInternal = true
		labelIDs = append(labelIDs, labelInternalUser)
	} else {
		labelIDs = append(labelIDs, labelSupportReview)
		if p.MatrixWhoami != nil && p.MatrixWhoami.UserInfo.Channel == "NIGHTLY" {
			labelIDs = append(labelIDs, labelNightlyUser)
		}
	}
	if p.MatrixWhoami != nil {
		if !isInternal && p.MatrixWhoami.UserInfo.CreatedAt.Add(24*time.Hour).After(time.Now()) {
			labelIDs = append(labelIDs, labelNewUser)
		}
	}

	if bridge != "" && bridge != "all" && bridge != "matrix" && bridge != "beeper" {
		if bridge == "android-sms" || bridge == "androidsms" {
			teamID = linearTeamAndroid
		} else {
			teamID = linearTeamBackend
		}
		if bridgeLabelID, ok := bridgeToLabelID[bridge]; ok {
			labelIDs = append(labelIDs, bridgeLabelID)
		}
	}
	if problem, ok := p.Data["problem"]; ok {
		if problem == problemBridgeRequest || problem == problemFeatureRequest || problem == problemSuggestion {
			teamID = linearTeamProduct
		}
		if problemLabelID, ok := problemToLabelID[problem]; ok {
			labelIDs = append(labelIDs, problemLabelID)
		}
	}
	if userPriority, ok := p.Data["user_priority"]; ok {
		if userPriorityLabelID, ok := userPriorityToLabelID[strings.ToLower(userPriority)]; ok {
			labelIDs = append(labelIDs, userPriorityLabelID)
		}
	}

	title, body := s.buildGenericIssueRequest(p, listingURL)

	fmt.Println("Creating issue in", teamID)
	fmt.Println("  Labels:", labelIDs)
	fmt.Println("  Subscribers:", subscriberIDs)
	fmt.Println("  Title:", title)

	var createResp CreateIssueResponse
	err := LinearRequest(&GraphQLRequest{
		Token: s.cfg.LinearToken,
		Query: mutationCreateIssue,
		Variables: map[string]interface{}{
			"input": map[string]interface{}{
				"teamId":        teamID,
				"title":         title,
				"description":   body,
				"labelIds":      labelIDs,
				"subscriberIds": subscriberIDs,
			},
		},
	}, &createResp)
	if err != nil {
		return err
	}

	log.Println("Created issue:", createResp.IssueCreate.Issue.URL)

	resp.ReportURL = createResp.IssueCreate.Issue.URL
	resp.IssueNumber = createResp.IssueCreate.Issue.Identifier

	fmt.Printf("  / %+v\n", createResp.IssueCreate)
	fmt.Println("Rageshake response:", resp)

	return nil
}

type webhookRequest struct {
	Payload     parsedPayload `json:"payload"`
	ListingURL  string        `json:"listing_url"`
	ReportURL   string        `json:"report_url"`
	IssueNumber string        `json:"issue_number"`
}

func (s *submitServer) submitWebhook(ctx context.Context, p parsedPayload, listingURL string, submitResp *submitResponse) error {
	if len(s.cfg.WebhookURL) == 0 {
		return nil
	}

	reqData := &webhookRequest{
		Payload:     p,
		ListingURL:  listingURL,
		ReportURL:   submitResp.ReportURL,
		IssueNumber: submitResp.IssueNumber,
	}

	var body bytes.Buffer
	var req *http.Request
	var resp *http.Response
	var err error
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	if err = json.NewEncoder(&body).Encode(reqData); err != nil {
		return fmt.Errorf("failed to encode JSON for webhook: %w", err)
	} else if req, err = http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.WebhookURL, &body); err != nil {
		return fmt.Errorf("failed to prepare webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if resp, err = http.DefaultClient.Do(req); err != nil {
		return fmt.Errorf("failed to send webhook request: %w", err)
	} else if resp.StatusCode < 200 || resp.StatusCode > 300 {
		return fmt.Errorf("unexpected webhook HTTP status code %d", resp.StatusCode)
	} else {
		return nil
	}
}

func buildReportTitle(p parsedPayload) string {
	// set the title to the first (non-empty) line of the user's report, if any
	trimmedUserText := strings.TrimSpace(p.UserText)
	if trimmedUserText == "" {
		trimmedUserText = "Untitled report"
	} else if i := strings.IndexAny(trimmedUserText, "\r\n"); i >= 0 {
		trimmedUserText = trimmedUserText[0:i]
	}
	userID := p.Data["user_id"]
	if len(userID) == 0 {
		userID = p.Data["unverified_user_id"]
		if len(userID) == 0 {
			userID = "unknown user"
		} else {
			userID = fmt.Sprintf("[unverified] %s", userID)
		}
	}
	userID = strings.TrimPrefix(strings.TrimSuffix(userID, ":beeper.com"), "@")
	title := fmt.Sprintf("%s: %s", userID, trimmedUserText)
	if len(title) > 200 {
		title = title[:200]
	}
	return title
}

func (s *submitServer) buildReportBody(p parsedPayload, listingURL string) *bytes.Buffer {
	var bodyBuf bytes.Buffer

	textLines := strings.Split(p.UserText, "\n")
	for i, line := range textLines {
		textLines[i] = fmt.Sprintf("> %s", html.EscapeString(line))
	}
	userText := strings.Join(textLines, "\n")

	if len(p.Data["user_id"]) == 0 && len(p.Data["unverified_user_id"]) > 0 {
		fmt.Fprintf(&bodyBuf, "Rageshake server was unable to verify the access token used to send this report. It is possible the user's session is corrupted, or that rageshake failed to talk to api server. The support room notice was not sent.\n\n")
	}

	if p.AppName == "beeper-desktop" && !strings.Contains(p.Data["User-Agent"], "Electron") && !p.IsInternal {
		fmt.Fprintf(&bodyBuf, "## User may be using unsupported environment like chat.beeper.com\n\n`User-Agent` field doesn't contain \"Electron\".\n\n")
	}

	fmt.Fprintf(&bodyBuf, "### User message:\n\n%s\n\n", userText)

	var authedListingURL string
	if len(p.Files) > 0 {
		parsed, _ := url.Parse(listingURL)
		parsed.User = url.UserPassword(s.cfg.BugsUser, s.cfg.BugsPass)
		authedListingURL = parsed.String()
	}
	for _, file := range p.Files {
		imageifier := ""
		fileURL := listingURL + "/" + file
		ext := strings.ToLower(filepath.Ext(file))
		if ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".gif" {
			imageifier = "!"
			fileURL = authedListingURL + "/" + file
		}
		fmt.Fprintf(
			&bodyBuf,
			"%s[%s](%s)\n",
			imageifier,
			file,
			fileURL,
		)
	}

	var dataKeys, eventDataKeys []string
	var eventSource string
	for k := range p.Data {
		switch k {
		case "event_id", "room_id", "event_timestamp":
			eventDataKeys = append(eventDataKeys, k)
		case "decrypted_event_source":
			eventSource = p.Data[k]
		default:
			dataKeys = append(dataKeys, k)
		}
	}
	sort.Strings(dataKeys)
	sort.Strings(eventDataKeys)

	printDataKeys(p, &bodyBuf, "Event data", eventDataKeys)
	if eventSource != "" {
		_, _ = fmt.Fprintf(&bodyBuf, "### Event source:\n\n```json\n%s\n```\n", eventSource)
	}
	printDataKeys(p, &bodyBuf, "Data from app", dataKeys)

	return &bodyBuf
}

func printDataKeys(p parsedPayload, output io.Writer, title string, keys []string) {
	if len(keys) == 0 {
		return
	}
	fmt.Fprintf(output, "### %s:\n\n```yaml\n", title)

	for _, k := range keys {
		v := p.Data[k]
		fmt.Fprintf(output, "%s: %s\n", k, v)
	}

	fmt.Fprintf(output, "```\n")
}

func (s *submitServer) buildGenericIssueRequest(p parsedPayload, listingURL string) (title, body string) {
	bodyBuf := s.buildReportBody(p, listingURL)

	// Add log links to the body
	fmt.Fprintf(bodyBuf, "\n### [Logs](%s)", listingURL)

	title = buildReportTitle(p)

	body = bodyBuf.String()

	return
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
	if err := os.WriteFile(fpath, b.Bytes(), 0644); err != nil {
		return err
	}
	return nil
}
