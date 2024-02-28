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
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

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

	LinearToken string `yaml:"linear_token"`

	APIServerURLs map[string]string `yaml:"api_server_url"`

	WebhookURL string `yaml:"webhook_url"`
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

	if cfg.LinearToken == "" {
		panic("No linear_token configured. Reporting bugs to Linear is disabled.")
	}
	err = fillEmailCache(cfg.LinearToken)
	if err != nil {
		log.Fatalln("Failed to fetch internal user IDs from Linear:", err)
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

	http.Handle("/api/submit", &submitServer{apiPrefix: apiPrefix, cfg: cfg})

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

func loadConfig(configPath string) (*config, error) {
	contents, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var cfg config
	if err = yaml.Unmarshal(contents, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
