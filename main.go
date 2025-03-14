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
	"regexp"
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

// defaultErrorReason is the default reason string when not present for a rejection condition
const defaultErrorReason string = "app or user text rejected"

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

// RejectionCondition contains the fields that can match a bug report for it to be rejected.
// All the (optional) fields must match for the rejection condition to apply
type RejectionCondition struct {
	// App name, applies only if not empty
	App string `yaml:"app"`
	// Version, applies only if not empty
	Version string `yaml:"version"`
	// Label, applies only if not empty
	Label string `yaml:"label"`
	// Message sent by the user, applies only if not empty
	UserTextMatch string `yaml:"usertext"`
	// Send this text to the client-side to inform the user why the server rejects the rageshake. Uses a default generic value if empty.
	Reason string `yaml:"reason"`
	// Send this text to the client-side to inform the user why the server rejects the rageshake. Uses a default error code REJECTED if empty.
	ErrorCode string `yaml:"errorcode"`
}

func (c RejectionCondition) matchesApp(p *payload) bool {
	// Empty `RejectionCondition.App` is a wildcard which matches anything
	return c.App == "" || c.App == p.AppName
}

func (c RejectionCondition) matchesVersion(p *payload) bool {
	version := ""
	if p.Data != nil {
		version = p.Data["Version"]
	}
	// Empty `RejectionCondition.Version` is a wildcard which matches anything
	return c.Version == "" || c.Version == version
}

func (c RejectionCondition) matchesLabel(p *payload) bool {
	// Empty `RejectionCondition.Label` is a wildcard which matches anything
	if c.Label == "" {
		return true
	}
	// Otherwise return true only if there is a label that matches
	labelMatch := false
	for _, l := range p.Labels {
		if l == c.Label {
			labelMatch = true
			break
		}
	}
	return labelMatch
}

func (c RejectionCondition) matchesUserText(p *payload) bool {
	// Empty `RejectionCondition.UserTextMatch` is a wildcard which matches anything
	return c.UserTextMatch == "" || regexp.MustCompile(c.UserTextMatch).MatchString(p.UserText)
}

// Returns a rejection reason and error code if the payload should be rejected by this condition, condition; otherwise returns `nil` for both results.
func (c RejectionCondition) shouldReject(p *payload) (*string, *string) {
	if c.matchesApp(p) && c.matchesVersion(p) && c.matchesLabel(p) && c.matchesUserText(p) {
		// RejectionCondition matches all of the conditions: we should reject this submission/
		var reason = defaultErrorReason
		if c.Reason != "" {
			reason = c.Reason
		}
		var code = ErrCodeRejected
		if c.ErrorCode != "" {
			code = c.ErrorCode
		}
		return &reason, &code
	}
	return nil, nil
}

// Returns a rejection reason and error code if the payload should be rejected by any condition, condition; otherwise returns `nil` for both results.
func (c *config) matchesRejectionCondition(p *payload) (*string, *string) {
	for _, rc := range c.RejectionConditions {
		reject, code := rc.shouldReject(p)
		if reject != nil {
			return reject, code
		}
	}
	return nil, nil
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

	for idx, condition := range cfg.RejectionConditions {
		if condition.ErrorCode != "" && !strings.HasPrefix(condition.ErrorCode, "REJECTED_") {
			return nil, fmt.Errorf("Rejected condition %d was invalid. `errorcode` must be use the namespace REJECTED_", idx);
		}
	}
	return &cfg, nil
}
