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
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// testParsePayload builds a /submit request with the given body, and calls
// parseRequest with it.
func testParsePayload(t *testing.T, body, contentType string) (p *payload) {
	req, err := http.NewRequest("POST", "/api/submit", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rr := httptest.NewRecorder()
	p = parseRequest(rr, req)

	if p == nil {
		t.Error("parseRequest returned nil")
	}
	return
}

func TestEmptyJson(t *testing.T) {
	body := "{}"

	// we just test it is parsed without errors for now
	testParsePayload(t, body, "application/json")
}

// check that we can unpick the json submitted by the android clients
func TestUnpickAndroidMangling(t *testing.T) {
	body := `{"text": "test ylc 001",
"version": "User : @ylc8001:matrix.org\nPhone : Lenovo P2a42\nVector version: 0:6:9\n",
"user_agent": "Android"
}`
	p := testParsePayload(t, body, "")
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
	body := `------WebKitFormBoundarySsdgl8Nq9voFyhdO
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
------WebKitFormBoundarySsdgl8Nq9voFyhdO--
`
	p := testParsePayload(t, body, "multipart/form-data; boundary=----WebKitFormBoundarySsdgl8Nq9voFyhdO")
	wanted := "test words."
	if p.Text != wanted {
		t.Errorf("User text: got %s, want %s", p.Text, wanted)
	}
	if len(p.Logs) != 2 {
		t.Errorf("Log length: got %d, want 2", len(p.Logs))
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
}
