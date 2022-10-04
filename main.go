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
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/go-github/github"
	"github.com/xanzy/go-gitlab"
	"golang.org/x/oauth2"

	"gopkg.in/yaml.v2"
)

var configPath = flag.String("config", "rageshake.yaml", "The path to the config file. For more information, see the config file in this repository.")
var bindAddr = flag.String("listen", ":9110", "The port to listen on.")

type config struct {
	// Username and password required to access the bug report listings
	BugsUser string `yaml:"listings_auth_user"`
	BugsPass string `yaml:"listings_auth_pass"`

	// External URI to /api
	APIPrefix string `yaml:"api_prefix"`

	// A GitHub personal access token, to create a GitHub issue for each report.
	GithubToken string `yaml:"github_token"`

	GithubProjectMappings map[string]string `yaml:"github_project_mappings"`

	GitlabURL   string `yaml:"gitlab_url"`
	GitlabToken string `yaml:"gitlab_token"`

	GitlabProjectMappings   map[string]int      `yaml:"gitlab_project_mappings"`
	GitlabProjectLabels     map[string][]string `yaml:"gitlab_project_labels"`
	GitlabIssueConfidential bool                `yaml:"gitlab_issue_confidential"`
	GitlabProblemLabels     map[string]string   `yaml:"gitlab_problem_labels"`

	LinearToken string `yaml:"linear_token"`

	HomeserverURLs map[string]string `yaml:"homeserver_url"`

	WebhookURL string `yaml:"webhook_url"`

	SlackWebhookURL string `yaml:"slack_webhook_url"`

	EmailAddresses []string `yaml:"email_addresses"`

	EmailFrom string `yaml:"email_from"`

	SMTPServer string `yaml:"smtp_server"`

	SMTPUsername string `yaml:"smtp_username"`

	SMTPPassword string `yaml:"smtp_password"`
}

func basicAuth(handler http.Handler, username, password, realm string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth() // pull creds from the request

		// check user and pass securely
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 || subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorised.\n"))
			return
		}

		handler.ServeHTTP(w, r)
	})
}

func main() {
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Invalid config file: %s", err)
	}

	var ghClient *github.Client

	if cfg.GithubToken == "" {
		fmt.Println("No github_token configured. Reporting bugs to github is disabled.")
	} else {
		ctx := context.Background()
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: cfg.GithubToken},
		)
		tc := oauth2.NewClient(ctx, ts)
		tc.Timeout = time.Duration(5) * time.Minute
		ghClient = github.NewClient(tc)
	}

	var glClient *gitlab.Client
	if cfg.GitlabToken == "" {
		fmt.Println("No gitlab_token configured. Reporting bugs to gitlab is disaled.")
	} else {
		glClient, err = gitlab.NewClient(cfg.GitlabToken, gitlab.WithBaseURL(cfg.GitlabURL))
		if err != nil {
			// This probably only happens if the base URL is invalid
			log.Fatalln("Failed to create GitLab client:", err)
		}
	}

	if cfg.LinearToken == "" {
		fmt.Println("No linear_token configured. Reporting bugs to Linear is disabled.")
	}

	var slack *slackClient

	if cfg.SlackWebhookURL == "" {
		fmt.Println("No slack_webhook_url configured. Reporting bugs to slack is disabled.")
	} else {
		slack = newSlackClient(cfg.SlackWebhookURL)
	}

	if len(cfg.EmailAddresses) > 0 && cfg.SMTPServer == "" {
		log.Fatal("Email address(es) specified but no smtp_server configured. Wrong configuration, aborting...")
	}

	apiPrefix := cfg.APIPrefix
	if apiPrefix == "" {
		_, port, err := net.SplitHostPort(*bindAddr)
		if err != nil {
			log.Fatal(err)
		}
		apiPrefix = fmt.Sprintf("http://localhost:%s/api", port)
	} else {
		// remove trailing /
		apiPrefix = strings.TrimRight(apiPrefix, "/")
	}
	log.Printf("Using %s/listing as public URI", apiPrefix)

	http.Handle("/api/submit", &submitServer{ghClient, glClient, apiPrefix, slack, cfg})

	// Make sure bugs directory exists
	_ = os.Mkdir("bugs", os.ModePerm)

	// serve files under "bugs"
	ls := &logServer{"bugs"}
	fs := http.StripPrefix("/api/listing/", ls)

	// set auth if env vars exist
	usr := cfg.BugsUser
	pass := cfg.BugsPass
	if usr == "" || pass == "" {
		fmt.Println("No listings_auth_user/pass configured. No authentication is running for /api/listing")
	} else {
		fs = basicAuth(fs, usr, pass, "Riot bug reports")
	}
	http.Handle("/api/listing/", fs)

	log.Println("Listening on", *bindAddr)

	log.Fatal(http.ListenAndServe(*bindAddr, nil))
}

func loadConfig(configPath string) (*config, error) {
	contents, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var cfg config
	if err = yaml.Unmarshal(contents, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
