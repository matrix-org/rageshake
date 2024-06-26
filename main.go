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
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/google/go-github/github"
	"github.com/xanzy/go-gitlab"
	"golang.org/x/oauth2"

	"gopkg.in/yaml.v2"

	_ "embed"
)

// DefaultIssueBodyTemplate is the default template used for `issue_body_template_file` in the config.
//
//go:embed templates/issue_body.tmpl
var DefaultIssueBodyTemplate string

// DefaultEmailBodyTemplate is the default template used for `email_body_template_file` in the config.
//
//go:embed templates/email_body.tmpl
var DefaultEmailBodyTemplate string

var configPath = flag.String("config", "rageshake.yaml", "The path to the config file. For more information, see the config file in this repository.")
var bindAddr = flag.String("listen", ":9110", "The port to listen on.")

type config struct {
	// Username and password required to access the bug report listings
	BugsUser string `yaml:"listings_auth_user"`
	BugsPass string `yaml:"listings_auth_pass"`

	// External URI to /api
	APIPrefix string `yaml:"api_prefix"`

	// Allowed rageshake app names
	AllowedAppNames []string `yaml:"allowed_app_names"`

	// List of rejection conditions
	RejectionConditions []RejectionCondition `yaml:"rejection_conditions"`

	// A GitHub personal access token, to create a GitHub issue for each report.
	GithubToken string `yaml:"github_token"`

	GithubProjectMappings map[string]string `yaml:"github_project_mappings"`

	GitlabURL   string `yaml:"gitlab_url"`
	GitlabToken string `yaml:"gitlab_token"`

	GitlabProjectMappings   map[string]int      `yaml:"gitlab_project_mappings"`
	GitlabProjectLabels     map[string][]string `yaml:"gitlab_project_labels"`
	GitlabIssueConfidential bool                `yaml:"gitlab_issue_confidential"`

	IssueBodyTemplateFile string `yaml:"issue_body_template_file"`
	EmailBodyTemplateFile string `yaml:"email_body_template_file"`

	SlackWebhookURL string `yaml:"slack_webhook_url"`

	EmailAddresses []string `yaml:"email_addresses"`

	EmailFrom string `yaml:"email_from"`

	SMTPServer string `yaml:"smtp_server"`

	SMTPUsername string `yaml:"smtp_username"`

	SMTPPassword string `yaml:"smtp_password"`

	GenericWebhookURLs []string `yaml:"generic_webhook_urls"`
}

// RejectionCondition contains the fields that should match a bug report for it to be rejected.
type RejectionCondition struct {
	// Required field: if a payload does not match this app name, the condition does not match.
	App string `yaml:"app"`
	// Optional: version that must also match in addition to the app and label. If empty, does not check version.
	Version string `yaml:"version"`
	// Optional: label that must also match in addition to the app and version. If empty, does not check label.
	Label string `yaml:"label"`
}

// shouldReject returns true if the app name AND version AND labels all match the rejection condition.
// If any one of these do not match the condition, it is not rejected.
func (c RejectionCondition) shouldReject(appName, version string, labels []string) bool {
	if appName != c.App {
		return false
	}
	// version was a condition and it doesn't match => accept it
	if version != c.Version && c.Version != "" {
		return false
	}

	// label was a condition and no label matches it => accept it
	if c.Label != "" {
		labelMatch := false
		for _, l := range labels {
			if l == c.Label {
				labelMatch = true
				break
			}
		}
		if !labelMatch {
			return false
		}
	}

	return true
}

func (c *config) matchesRejectionCondition(p *payload) bool {
	for _, rc := range c.RejectionConditions {
		version := ""
		if p.Data != nil {
			version = p.Data["Version"]
		}
		if rc.shouldReject(p.AppName, version, p.Labels) {
			return true
		}
	}
	return false
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

	var slack *slackClient

	if cfg.SlackWebhookURL == "" {
		fmt.Println("No slack_webhook_url configured. Reporting bugs to slack is disabled.")
	} else {
		slack = newSlackClient(cfg.SlackWebhookURL)
	}

	if len(cfg.EmailAddresses) > 0 && cfg.SMTPServer == "" {
		log.Fatal("Email address(es) specified but no smtp_server configured. Wrong configuration, aborting...")
	}

	genericWebhookClient := configureGenericWebhookClient(cfg)

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

	appNameMap := configureAppNameMap(cfg)

	log.Printf("Using %s/listing as public URI", apiPrefix)

	rand.Seed(time.Now().UnixNano())
	http.Handle("/api/submit", &submitServer{
		issueTemplate:        parseTemplate(DefaultIssueBodyTemplate, cfg.IssueBodyTemplateFile, "issue"),
		emailTemplate:        parseTemplate(DefaultEmailBodyTemplate, cfg.EmailBodyTemplateFile, "email"),
		ghClient:             ghClient,
		glClient:             glClient,
		apiPrefix:            apiPrefix,
		slack:                slack,
		genericWebhookClient: genericWebhookClient,
		allowedAppNameMap:    appNameMap,
		cfg:                  cfg,
	})

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

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})

	log.Println("Listening on", *bindAddr)

	log.Fatal(http.ListenAndServe(*bindAddr, nil))
}

// parseTemplate parses a template file, with fallback to default.
//
// If `templateFilePath` is non-empty, it is used as the name of a file to read. Otherwise, `defaultTemplate` is
// used.
//
// The template text is then parsed into a template named `templateName`.
func parseTemplate(defaultTemplate string, templateFilePath string, templateName string) *template.Template {
	templateText := defaultTemplate
	if templateFilePath != "" {
		issueTemplateBytes, err := os.ReadFile(templateFilePath)
		if err != nil {
			log.Fatalf("Unable to read template file `%s`: %s", templateFilePath, err)
		}
		templateText = string(issueTemplateBytes)
	}
	parsedTemplate, err := template.New(templateName).Parse(templateText)
	if err != nil {
		log.Fatalf("Invalid template file %s in config file: %s", templateFilePath, err)
	}
	return parsedTemplate
}

func configureAppNameMap(cfg *config) map[string]bool {
	if len(cfg.AllowedAppNames) == 0 {
		fmt.Println("Warning: allowed_app_names is empty. Accepting requests from all app names")
	}
	var allowedAppNameMap = make(map[string]bool)
	for _, app := range cfg.AllowedAppNames {
		allowedAppNameMap[app] = true
	}
	return allowedAppNameMap
}

func configureGenericWebhookClient(cfg *config) *http.Client {
	if len(cfg.GenericWebhookURLs) == 0 {
		fmt.Println("No generic_webhook_urls configured.")
		return nil
	}
	fmt.Println("Will forward metadata of all requests to ", cfg.GenericWebhookURLs)
	return &http.Client{
		Timeout: time.Second * 300,
	}
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
	// sanity check rejection conditions
	for _, rc := range cfg.RejectionConditions {
		if rc.App == "" {
			fmt.Println("rejection_condition missing an app field so will never match anything.")
		}
		if rc.Label == "" && rc.Version == "" {
			fmt.Println("rejection_condition missing both label and version so will always match, specify label and/or version")
		}
	}
	return &cfg, nil
}
