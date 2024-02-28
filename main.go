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

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v2"
)

var configPath = flag.String("config", "rageshake.yaml", "The path to the config file. For more information, see the config file in this repository.")
var bindAddr = flag.String("listen", ":9110", "The port to listen on.")

type config struct {
	// Username and password required to access the bug report listings
	BugsUser      string `yaml:"listings_auth_user"`
	BugsPass      string `yaml:"listings_auth_pass"`
	BugsJWTSecret string `yaml:"listings_jwt_secret"`

	// External URI to /api
	APIPrefix string `yaml:"api_prefix"`

	LinearToken string `yaml:"linear_token"`

	APIServerURLs map[string]string `yaml:"api_server_url"`

	WebhookURL string `yaml:"webhook_url"`
}

const (
	rageshakeIssuer = "com.beeper.rageshake"
	apiServerIssuer = "com.beeper.api-server"
)

func basicAuthOrJWTAuthenticated(handler http.Handler, username, password, realm string, jwtSecret []byte) http.Handler {
	if (username == "" || password == "") && len(jwtSecret) == 0 {
		panic("Either username or password for basic auth must be set, or JWT secret must be set, or both")
	}

	unauthorized := func(w http.ResponseWriter) {
		w.WriteHeader(401)
		w.Write([]byte("Unauthorised.\n"))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth() // pull creds from the request
		if !ok && len(jwtSecret) == 0 { // if no basic auth and no JWT auth, return unauthorized
			unauthorized(w)
			return
		} else if !ok { // if no basic auth, try to do JWT auth
			token, err := jwt.ParseWithClaims(r.URL.Query().Get("tok"), &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
				// Don't forget to validate the alg is what you expect:
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return jwtSecret, nil
			})
			if err != nil {
				log.Printf("Error parsing JWT: %v", err)
				unauthorized(w)
				return
			}

			claims, ok := token.Claims.(*jwt.RegisteredClaims)
			if !token.Valid || !ok {
				log.Printf("Token invalid or claims not RegisteredClaims: %v", err)
				unauthorized(w)
				return
			} else if claims.Issuer != rageshakeIssuer && claims.Issuer != apiServerIssuer {
				log.Printf("Token issuer not rageshake or API server: %s", claims.Issuer)
				unauthorized(w)
				return
			} else if claims.Subject != r.URL.Path {
				log.Printf("Token subject (%s) not the request path (%s)", claims.Subject, r.URL.Path)
				unauthorized(w)
				return
			}

			log.Printf("Valid token from %s for accessing %s", claims.Issuer, claims.Subject)
		} else if subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 || subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 { // check user and pass securely
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			unauthorized(w)
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
	fs := basicAuthOrJWTAuthenticated(ls, cfg.BugsUser, cfg.BugsPass, "Riot bug reports", []byte(cfg.BugsJWTSecret))
	http.Handle("/api/listing/", http.StripPrefix("/api/listing/", fs))

	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
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
