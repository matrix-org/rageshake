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
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"text/template"
)

// testParsePayload builds a /submit request with the given body, and calls
// parseRequest with it.
//
// if tempDir is empty, a new temp dir is created, and deleted when the test
// completes.
func testParsePayload(t *testing.T, body, contentType string, tempDir string) (*payload, *http.Response) {
	req, err := http.NewRequest("POST", "/api/submit", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// temporary dir for the uploaded files
	if tempDir == "" {
		tempDir = mkTempDir(t)
		defer os.RemoveAll(tempDir)
	}

	rr := httptest.NewRecorder()
	p := parseRequest(rr, req, tempDir)
	return p, rr.Result()
}

func submitSimpleRequestToServer(t *testing.T, allowedAppNameMap map[string]bool, body string) int {
	// Submit a request without files to the server and return statusCode
	// Could be extended with more complicated config; aimed here just to
	// test options for allowedAppNameMap

	req, err := http.NewRequest("POST", "/api/submit", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	w := httptest.NewRecorder()

	var cfg config
	s := &submitServer{nil, nil, nil, nil, "/", nil, nil, allowedAppNameMap, &cfg}

	s.ServeHTTP(w, req)
	rsp := w.Result()
	return rsp.StatusCode
}

func TestAppNames(t *testing.T) {
	body := `{
    "app": "alice",
    "logs": [ ],
    "text": "test message",
    "user_agent": "Mozilla/0.9",
    "version": "0.9.9"
}`
	validAppNameMap := map[string]bool{
		"alice": true,
	}
	if submitSimpleRequestToServer(t, validAppNameMap, body) != 200 {
		t.Fatal("matching app was not accepted")
	}

	invalidAppNameMap := map[string]bool{
		"bob": true,
	}
	if submitSimpleRequestToServer(t, invalidAppNameMap, body) != 400 {
		t.Fatal("nonmatching app was not rejected")
	}

	emptyAppNameMap := make(map[string]bool)
	if submitSimpleRequestToServer(t, emptyAppNameMap, body) != 200 {
		t.Fatal("empty map did not allow all")
	}
}

func TestEmptyJson(t *testing.T) {
	body := "{}"

	// we just test it is parsed without errors for now
	p, _ := testParsePayload(t, body, "application/json", "")
	if p == nil {
		t.Fatal("parseRequest returned nil")
	}
	if len(p.Labels) != 0 {
		t.Errorf("Labels: got %#v, want []", p.Labels)
	}
}

func TestJsonUpload(t *testing.T) {
	reportDir := mkTempDir(t)
	defer os.RemoveAll(reportDir)

	body := `{
    "app": "riot-web",
    "logs": [
        {
            "id": "instance-0.99152119701215051494400738905",
            "lines": "line1\nline2"
        }
    ],
    "text": "test message",
    "user_agent": "Mozilla",
    "version": "0.9.9"
}`

	p, _ := testParsePayload(t, body, "application/json", reportDir)

	if p == nil {
		t.Fatal("parseRequest returned nil")
	}

	wanted := "test message"
	if p.UserText != wanted {
		t.Errorf("user text: got %s, want %s", p.UserText, wanted)
	}
	wanted = "riot-web"
	if p.AppName != wanted {
		t.Errorf("appname: got %s, want %s", p.AppName, wanted)
	}
	wanted = "0.9.9"
	if p.Data["Version"] != wanted {
		t.Errorf("version: got %s, want %s", p.Data["Version"], wanted)
	}

	checkUploadedFile(t, reportDir, "logs-0000.log.gz", true, "line1\nline2")
}

func TestMultipartUpload(t *testing.T) {
	reportDir := mkTempDir(t)
	defer os.RemoveAll(reportDir)

	p, _ := testParsePayload(t, multipartBody(),
		"multipart/form-data; boundary=----WebKitFormBoundarySsdgl8Nq9voFyhdO",
		reportDir,
	)

	if p == nil {
		t.Fatal("parseRequest returned nil")
	}

	checkParsedMultipartUpload(t, p)

	// check logs uploaded correctly
	checkUploadedFile(t, reportDir, "logs-0000.log.gz", true, "log\nlog\nlog")
	checkUploadedFile(t, reportDir, "console.0.log.gz", true, "log")
	checkUploadedFile(t, reportDir, "logs-0002.log.gz", true, "test\n")

	// check file uploaded correctly
	checkUploadedFile(t, reportDir, "passwd.txt", false, "bibblybobbly")
	checkUploadedFile(t, reportDir, "crash.log.gz", true, "test\n")
}

func multipartBody() (body string) {
	body = `------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="text"

test words.
------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="app"

riot-web
------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="version"

UNKNOWN
------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="user_agent"

Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36
------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="test-field"

Test data
------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="log"; filename="instance-0.215954445471346461492087122412"
Content-Type: text/plain

log
log
log
------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="log"; filename="console.0.log"
Content-Type: text/plain

log
`

	body += `------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="compressed-log"; filename="instance-0.0109372050779190651492004373866"
Content-Type: application/octet-stream

`
	body += string([]byte{
		0x1f, 0x8b, 0x08, 0x00, 0xbf, 0xd8, 0xf5, 0x58, 0x00, 0x03,
		0x2b, 0x49, 0x2d, 0x2e, 0xe1, 0x02, 0x00,
		0xc6, 0x35, 0xb9, 0x3b, 0x05, 0x00, 0x00, 0x00,
		0x0a,
	})

	body += `------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="file"; filename="passwd.txt"
Content-Type: application/octet-stream

bibblybobbly
`
	body += `------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="compressed-log"; filename="crash.log.gz"
Content-Type: application/octet-stream

`
	body += string([]byte{
		0x1f, 0x8b, 0x08, 0x00, 0xbf, 0xd8, 0xf5, 0x58, 0x00, 0x03,
		0x2b, 0x49, 0x2d, 0x2e, 0xe1, 0x02, 0x00,
		0xc6, 0x35, 0xb9, 0x3b, 0x05, 0x00, 0x00, 0x00,
		0x0a,
	})

	body += "------WebKitFormBoundarySsdgl8Nq9voFyhdO--\n"
	return
}

func checkParsedMultipartUpload(t *testing.T, p *payload) {
	wanted := "test words."
	if p.UserText != wanted {
		t.Errorf("User text: got %s, want %s", p.UserText, wanted)
	}
	if len(p.Logs) != 4 {
		t.Errorf("Log length: got %d, want 4", len(p.Logs))
	}
	// One extra data field to account for User Agent being parsed into two fields
	if len(p.Data) != 4 {
		t.Errorf("Data length: got %d, want 4", len(p.Data))
	}
	if len(p.Labels) != 0 {
		t.Errorf("Labels: got %#v, want []", p.Labels)
	}
	wanted = "Test data"
	if p.Data["test-field"] != wanted {
		t.Errorf("test-field: got %s, want %s", p.Data["test-field"], wanted)
	}
	wanted = "logs-0000.log.gz"
	if p.Logs[0] != wanted {
		t.Errorf("Log 0: got %s, want %s", p.Logs[0], wanted)
	}
	wanted = "console.0.log.gz"
	if p.Logs[1] != wanted {
		t.Errorf("Log 1: got %s, want %s", p.Logs[1], wanted)
	}
	wanted = "logs-0002.log.gz"
	if p.Logs[2] != wanted {
		t.Errorf("Log 2: got %s, want %s", p.Logs[2], wanted)
	}
	wanted = "crash.log.gz"
	if p.Logs[3] != wanted {
		t.Errorf("Log 3: got %s, want %s", p.Logs[3], wanted)
	}
}

func TestLabels(t *testing.T) {
	body := `------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="label"

label1
------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="label"

label2
------WebKitFormBoundarySsdgl8Nq9voFyhdO--
`
	p, _ := testParsePayload(t, body,
		"multipart/form-data; boundary=----WebKitFormBoundarySsdgl8Nq9voFyhdO",
		"",
	)

	if p == nil {
		t.Fatal("parseRequest returned nil")
	}

	wantedLabels := []string{"label1", "label2"}
	if !stringSlicesEqual(p.Labels, wantedLabels) {
		t.Errorf("Labels: got %v, want %v", p.Labels, wantedLabels)
	}
}

func stringSlicesEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}

	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

/* FIXME these should just give a message in the details file now
func TestEmptyFilename(t *testing.T) {
	body := `------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="file"

file
------WebKitFormBoundarySsdgl8Nq9voFyhdO--
`
	p, resp := testParsePayload(t, body, "multipart/form-data; boundary=----WebKitFormBoundarySsdgl8Nq9voFyhdO", "")
	if p != nil {
		t.Error("parsePayload accepted upload with no filename")
	}

	if resp.StatusCode != 400 {
		t.Errorf("response code: got %v, want %v", resp.StatusCode, 400)
	}
}

func TestBadFilename(t *testing.T) {
	body := `------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="file"; filename="etc/passwd"

file
------WebKitFormBoundarySsdgl8Nq9voFyhdO--
`
	p, resp := testParsePayload(t, body, "multipart/form-data; boundary=----WebKitFormBoundarySsdgl8Nq9voFyhdO", "")
	if p != nil {
		t.Error("parsePayload accepted upload with bad filename")
	}

	if resp.StatusCode != 400 {
		t.Errorf("response code: got %v, want %v", resp.StatusCode, 400)
	}
}
*/

func checkUploadedFile(t *testing.T, reportDir, leafName string, gzipped bool, wanted string) {
	fi, err := os.Open(filepath.Join(reportDir, leafName))
	if err != nil {
		t.Errorf("unable to open uploaded file %s: %v", leafName, err)
		return
	}
	defer fi.Close()
	var rdr io.Reader
	if !gzipped {
		rdr = fi
	} else {
		gz, err2 := gzip.NewReader(fi)
		if err2 != nil {
			t.Errorf("unable to ungzip uploaded file %s: %v", leafName, err2)
			return
		}
		defer gz.Close()
		rdr = gz
	}
	dat, err := ioutil.ReadAll(rdr)
	if err != nil {
		t.Errorf("unable to read uploaded file %s: %v", leafName, err)
		return
	}

	datstr := string(dat)
	if datstr != wanted {
		t.Errorf("File %s: got %s, want %s", leafName, datstr, wanted)
	}
}

func mkTempDir(t *testing.T) string {
	td, err := ioutil.TempDir("", "rageshake_test")
	if err != nil {
		t.Fatal(err)
	}
	return td
}

/*****************************************************************************
 *
 * buildGithubIssueRequest tests
 */

// General test of Github issue formatting.
func TestBuildGithubIssue(t *testing.T) {
	body := `------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="text"


test words.
------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="app"

riot-web
------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="User-Agent"

xxx
------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="user_id"

id
------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="device_id"

id
------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="version"

1
------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="file"; filename="passwd.txt"

file
------WebKitFormBoundarySsdgl8Nq9voFyhdO--
`
	p, _ := testParsePayload(t, body,
		"multipart/form-data; boundary=----WebKitFormBoundarySsdgl8Nq9voFyhdO",
		"",
	)

	if p == nil {
		t.Fatal("parseRequest returned nil")
	}

	parsedIssueTemplate := template.Must(template.New("issue").Parse(DefaultIssueBodyTemplate))
	issueReq, err := buildGithubIssueRequest(*p, "http://test/listing/foo", parsedIssueTemplate)
	if err != nil {
		t.Fatalf("Error building issue request: %s", err)
	}

	if *issueReq.Title != "test words." {
		t.Errorf("Title: got %s, want %s", *issueReq.Title, "test words.")
	}
	expectedBody := "User message:\n\ntest words.\n\nUser-Agent: `xxx`\nVersion: `1`\ndevice_id: `id`\nuser_id: `id`\n\n[Logs](http://test/listing/foo) ([archive](http://test/listing/foo?format=tar.gz)) / [passwd.txt](http://test/listing/foo/passwd.txt)\n"
	if *issueReq.Body != expectedBody {
		t.Errorf("Body: got %s, want %s", *issueReq.Body, expectedBody)
	}
}

func TestBuildGithubIssueLeadingNewline(t *testing.T) {
	body := `------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="text"


test words.
------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="app"

riot-web
------WebKitFormBoundarySsdgl8Nq9voFyhdO--
`
	p, _ := testParsePayload(t, body,
		"multipart/form-data; boundary=----WebKitFormBoundarySsdgl8Nq9voFyhdO",
		"",
	)

	if p == nil {
		t.Fatal("parseRequest returned nil")
	}

	parsedIssueTemplate := template.Must(template.New("issue").Parse(DefaultIssueBodyTemplate))
	issueReq, err := buildGithubIssueRequest(*p, "http://test/listing/foo", parsedIssueTemplate)
	if err != nil {
		t.Fatalf("Error building issue request: %s", err)
	}

	if *issueReq.Title != "test words." {
		t.Errorf("Title: got %s, want %s", *issueReq.Title, "test words.")
	}
	expectedBody := "User message:\n\ntest words.\n"
	if !strings.HasPrefix(*issueReq.Body, expectedBody) {
		t.Errorf("Body: got %s, want %s", *issueReq.Body, expectedBody)
	}
}

func TestBuildGithubIssueEmptyBody(t *testing.T) {
	body := `------WebKitFormBoundarySsdgl8Nq9voFyhdO
Content-Disposition: form-data; name="text"

------WebKitFormBoundarySsdgl8Nq9voFyhdO--
`
	p, _ := testParsePayload(t, body,
		"multipart/form-data; boundary=----WebKitFormBoundarySsdgl8Nq9voFyhdO",
		"",
	)

	if p == nil {
		t.Fatal("parseRequest returned nil")
	}

	parsedIssueTemplate := template.Must(template.New("issue").Parse(DefaultIssueBodyTemplate))
	issueReq, err := buildGithubIssueRequest(*p, "http://test/listing/foo", parsedIssueTemplate)
	if err != nil {
		t.Fatalf("Error building issue request: %s", err)
	}

	if *issueReq.Title != "Untitled report" {
		t.Errorf("Title: got %s, want %s", *issueReq.Title, "Untitled report")
	}
	expectedBody := "User message:\n\n\n"
	if !strings.HasPrefix(*issueReq.Body, expectedBody) {
		t.Errorf("Body: got %s, want %s", *issueReq.Body, expectedBody)
	}
}

func TestSortDataKeys(t *testing.T) {
	expect := `
Number of logs: 0
Application: 
Labels: 
User-Agent: xxx
Version: 1
device_id: id
user_id: id
	`
	expect = strings.TrimSpace(expect)
	sample := []struct {
		data map[string]string
	}{
		{
			map[string]string{
				"Version":    "1",
				"User-Agent": "xxx",
				"user_id":    "id",
				"device_id":  "id",
			},
		},
		{
			map[string]string{
				"user_id":    "id",
				"device_id":  "id",
				"Version":    "1",
				"User-Agent": "xxx",
			},
		},
	}
	var buf bytes.Buffer
	for _, v := range sample {
		p := payload{Data: v.data}
		buf.Reset()
		p.WriteTo(&buf)
		got := strings.TrimSpace(buf.String())
		if got != expect {
			t.Errorf("expected %s got %s", expect, got)
		}
	}

	parsedIssueTemplate := template.Must(template.New("issue").Parse(DefaultIssueBodyTemplate))
	for k, v := range sample {
		p := payload{Data: v.data}
		res, err := buildGithubIssueRequest(p, "", parsedIssueTemplate)
		if err != nil {
			t.Fatalf("Error building issue request: %s", err)
		}
		got := *res.Body
		if k == 0 {
			expect = got
			continue
		}
		if got != expect {
			t.Errorf("expected %s got %s", expect, got)
		}
	}
}

func TestParseUserAgent(t *testing.T) {
	reportDir := mkTempDir(t)
	defer os.RemoveAll(reportDir)

	body := `{
    "app": "riot-web",
    "logs": [],
    "text": "test message",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.91 Safari/537.3",
    "version": "0.9.9"
}`

	p, _ := testParsePayload(t, body, "application/json", reportDir)

	if p == nil {
		t.Fatal("parseRequest returned nil")
	}

	wanted := "Chrome 130.0.6723 on Windows 10 running on Other device"
	if p.Data["User-Agent"] != wanted {
		t.Errorf("user agent: got %s, want %s", p.Data["User-Agent"], wanted)
	}
}
