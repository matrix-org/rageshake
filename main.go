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
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/rs/zerolog"
	globallog "github.com/rs/zerolog/log"
	"go.mau.fi/zeroconfig"
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

	LinearToken         string            `yaml:"linear_token"`
	LinearTokenOverride map[string]string `yaml:"linear_token_override"`

	APIServerURLs map[string]string `yaml:"api_server_url"`

	WebhookURL string `yaml:"webhook_url"`

	Logging zeroconfig.Config `yaml:"logging"`

	// S3 configuration
	S3Endpoint        string `yaml:"s3_endpoint"`
	S3AccessKeyID     string `yaml:"s3_access_key_id"`
	S3SecretAccessKey string `yaml:"s3_secret_access_key"`
	S3Bucket          string `yaml:"s3_bucket"`
	S3UseSSL          bool   `yaml:"s3_use_ssl"`
	S3Region		  string `yaml:"s3_region"`
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
		w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
		w.WriteHeader(401)
		w.Write([]byte("Unauthorised.\n"))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := zerolog.Ctx(r.Context())

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
				log.Err(err).Msg("Error parsing JWT")
				unauthorized(w)
				return
			}

			claims, ok := token.Claims.(*jwt.RegisteredClaims)
			if !token.Valid || !ok {
				log.Error().Msg("Token invalid or claims not RegisteredClaims")
				unauthorized(w)
				return
			} else if claims.Issuer != rageshakeIssuer && claims.Issuer != apiServerIssuer {
				log.Error().Str("issuer", claims.Issuer).Msg("Token issuer not rageshake or API server")
				unauthorized(w)
				return
			} else if claims.Subject != r.URL.Path {
				log.Error().Str("subject", claims.Subject).Str("path", r.URL.Path).Msg("Token subject not the request path")
				unauthorized(w)
				return
			}

			log.Info().Str("subject", claims.Subject).Str("issuer", claims.Issuer).Msg("Valid token")
		} else if subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 || subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 { // check user and pass securely
			unauthorized(w)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

// Add a global S3 client
var s3Client *minio.Client

func main() {
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		globallog.Fatal().Err(err).Str("config_path", *configPath).Msg("Failed to load config")
	}
	log, err := cfg.Logging.Compile()
	if err != nil {
		globallog.Fatal().Err(err).Msg("Failed to compile logging configuration")
	}
	zerolog.DefaultContextLogger = log

	if cfg.LinearToken == "" {
		log.Error().Msg("No linear_token configured. Reporting bugs to Linear is disabled.")
	} else {
		err = fillEmailCache(context.TODO(), cfg.LinearToken)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to fetch internal user IDs from Linear")
		}
	}

	apiPrefix := cfg.APIPrefix
	if apiPrefix == "" {
		_, port, err := net.SplitHostPort(*bindAddr)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to parse bind address")
		}
		apiPrefix = fmt.Sprintf("http://localhost:%s/api", port)
	} else {
		// remove trailing /
		apiPrefix = strings.TrimRight(apiPrefix, "/")
	}

	// Initialize S3 client
	s3Client, err = minio.New(cfg.S3Endpoint, &minio.Options{
		Region: cfg.S3Region,
		Creds:  credentials.NewStaticV4(cfg.S3AccessKeyID, cfg.S3SecretAccessKey, ""),
		Secure: cfg.S3UseSSL,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize S3 client")
	}
	// Ensure bucket exists
	ctx := context.Background()
	exists, err := s3Client.BucketExists(ctx, cfg.S3Bucket)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to check S3 bucket")
	}
	if !exists {
		err = s3Client.MakeBucket(ctx, cfg.S3Bucket, minio.MakeBucketOptions{})
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create S3 bucket")
		}
	}

	http.Handle("/api/submit", &submitServer{
		apiPrefix: apiPrefix,
		cfg:       cfg,
		s3Client:  s3Client,
		s3Bucket:  cfg.S3Bucket,
	})

	ls := &logServer{
		root: "bugs",
	}
	fs := basicAuthOrJWTAuthenticated(ls, cfg.BugsUser, cfg.BugsPass, "Riot bug reports", []byte(cfg.BugsJWTSecret))
	http.Handle("/api/listing/", http.StripPrefix("/api/listing/", fs))

	s3ls := &s3LogServer{
		s3Client: s3Client,
		s3Bucket: cfg.S3Bucket,
	}
	s3fs := basicAuthOrJWTAuthenticated(s3ls, cfg.BugsUser, cfg.BugsPass, "Riot bug reports", []byte(cfg.BugsJWTSecret))
	http.Handle("/api/listingS3/", http.StripPrefix("/api/listingS3/", s3fs))

	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok")
	})

	log.Info().
		Str("api_prefix", apiPrefix).
		Str("bind_addr", *bindAddr).
		Msg("Starting rageshake server HTTP listener")

	if err := http.ListenAndServe(*bindAddr, nil); err != nil {
		log.Fatal().Err(err).Msg("HTTP listener failed")
	}
}

func loadConfig(configPath string) (*config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	var cfg config
	err = yaml.NewDecoder(file).Decode(&cfg)
	return &cfg, err
}
