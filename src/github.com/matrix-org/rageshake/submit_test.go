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
