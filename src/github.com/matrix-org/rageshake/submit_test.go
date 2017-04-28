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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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

func TestEmptyJson(t *testing.T) {
	body := "{}"

	// we just test it is parsed without errors for now
	p, _ := testParsePayload(t, body, "application/json", "")
	if p == nil {
		t.Fatal("parseRequest returned nil")
	}
}

// check that we can unpick the json submitted by the android clients
func TestUnpickAndroidMangling(t *testing.T) {
	body := `{"text": "test ylc 001",
"version": "User : @ylc8001:matrix.org\nPhone : Lenovo P2a42\nVector version: 0:6:9\n",
"user_agent": "Android"
}`
	p, _ := testParsePayload(t, body, "", "")
	if p == nil {
		t.Fatal("parseRequest returned nil")
	}
	if p.Text != "test ylc 001" {
		t.Errorf("user text: got %s, want %s", p.Text, "test ylc 001")
	}
	if p.AppName != "riot-android" {
		t.Errorf("appname: got %s, want %s", p.AppName, "riot-android")
	}
	if p.Version != "" {
		t.Errorf("version: got %s, want ''", p.Version)
	}
	if p.Data["User"] != "@ylc8001:matrix.org" {
		t.Errorf("data.user: got %s, want %s", p.Data["User"], "@ylc8001:matrix.org")
	}
	if p.Data["Phone"] != "Lenovo P2a42" {
		t.Errorf("data.phone: got %s, want %s", p.Data["Phone"], "Lenovo P2a42")
	}
	if p.Data["Vector version"] != "0:6:9" {
		t.Errorf("data.version: got %s, want %s", p.Data["Version"], "0:6:9")
	}
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

	// check file uploaded correctly
	dat, err := ioutil.ReadFile(filepath.Join(reportDir, "passwd.txt"))
	if err != nil {
		t.Error("unable to read uploaded file", err)
	} else {
		datstr := string(dat)
		wanted := "bibblybobbly"
		if datstr != wanted {
			t.Errorf("File contents: got %s, want %s", datstr, wanted)
		}
	}
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
Content-Disposition: form-data; name="log"; filename="instance-0.067644760733513781492004890379"
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
	body += "------WebKitFormBoundarySsdgl8Nq9voFyhdO--\n"
	return
}

func checkParsedMultipartUpload(t *testing.T, p *payload) {
	wanted := "test words."
	if p.Text != wanted {
		t.Errorf("User text: got %s, want %s", p.Text, wanted)
	}
	if len(p.Logs) != 3 {
		t.Errorf("Log length: got %d, want 3", len(p.Logs))
	}
	if len(p.Data) != 1 {
		t.Errorf("Data length: got %d, want 1", len(p.Data))
	}
	wanted = "Test data"
	if p.Data["test-field"] != wanted {
		t.Errorf("test-field: got %s, want %s", p.Data["test-field"], wanted)
	}
	wanted = "log\nlog\nlog"
	if p.Logs[0].Lines != wanted {
		t.Errorf("Log 0: got %s, want %s", p.Logs[0].Lines, wanted)
	}
	wanted = "instance-0.215954445471346461492087122412"
	if p.Logs[0].ID != wanted {
		t.Errorf("Log 0 ID: got %s, want %s", p.Logs[0].ID, wanted)
	}
	wanted = "log"
	if p.Logs[1].Lines != wanted {
		t.Errorf("Log 1: got %s, want %s", p.Logs[1].Lines, wanted)
	}
	wanted = "instance-0.067644760733513781492004890379"
	if p.Logs[1].ID != wanted {
		t.Errorf("Log 1 ID: got %s, want %s", p.Logs[1].ID, wanted)
	}
	wanted = "test\n"
	if p.Logs[2].Lines != wanted {
		t.Errorf("Log 2: got %s, want %s", p.Logs[2].Lines, wanted)
	}
}

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

func mkTempDir(t *testing.T) string {
	td, err := ioutil.TempDir("", "rageshake_test")
	if err != nil {
		t.Fatal(err)
	}
	return td
}
