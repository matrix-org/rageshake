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
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
)

// logServer is an http.handler which will serve up bugreports
type logServer struct {
	root string
}

func (f *logServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upath := r.URL.Path
	log := zerolog.Ctx(r.Context()).With().
		Str("component", "log_server").
		Str("url_path", upath).
		Logger()
	ctx := log.WithContext(r.Context())

	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
		r.URL.Path = upath
	}

	log.Info().Msg("Serving report logs")

	// eliminate ., .., //, etc
	upath = path.Clean(upath)

	// reject some dodgy paths. This is based on the code for http.Dir.Open (see https://golang.org/src/net/http/fs.go#L37).
	//
	// the check for '..' is a sanity-check because my understanding of `path.Clean` is that it should never return
	// a value including '..' for input starting with '/'. It's taken from the code for http.ServeFile
	// (https://golang.org/src/net/http/fs.go#L637).
	if containsDotDot(upath) || strings.Contains(upath, "\x00") || (filepath.Separator != '/' && strings.ContainsRune(upath, filepath.Separator)) {
		http.Error(w, "invalid URL path", http.StatusBadRequest)
		return
	}

	// convert to abs path
	upath, err := filepath.Abs(filepath.Join(f.root, filepath.FromSlash(upath)))

	if err != nil {
		msg, code := toHTTPError(err)
		http.Error(w, msg, code)
		return
	}

	serveFile(ctx, w, r, upath)
}

func serveFile(ctx context.Context, w http.ResponseWriter, r *http.Request, path string) {
	log := zerolog.Ctx(ctx).With().Str("action", "serve_file").Logger()
	d, err := os.Stat(path)
	if err != nil {
		msg, code := toHTTPError(err)
		http.Error(w, msg, code)
		return
	}

	// for anti-XSS belt-and-braces, set a very restrictive CSP
	w.Header().Set("Content-Security-Policy", "default-src: none")

	// if it's a directory, serve a listing
	if d.IsDir() {
		log.Info().Msg("Serving listing")
		http.ServeFile(w, r, path)
		return
	}

	// if it's a gzipped log file, serve it as text
	if strings.HasSuffix(path, ".gz") {
		serveGzippedFile(w, r, path, d.Size())
		return
	}

	// otherwise, limit ourselves to a number of known-safe content-types, to
	// guard against XSS vulnerabilities.
	// http.serveFile preserves the content-type header if one is already set.
	w.Header().Set("Content-Type", extensionToMimeType(path))

	http.ServeFile(w, r, path)
}

// extensionToMimeType returns a suitable mime type for the given filename
//
// Unlike mime.TypeByExtension, the results are limited to a set of types which
// should be safe to serve to a browser without introducing XSS vulnerabilities.
func extensionToMimeType(path string) string {
	if strings.HasSuffix(path, ".txt") {
		// anyone uploading text in anything other than utf-8 needs to be
		// re-educated.
		return "text/plain; charset=utf-8"
	}
	if strings.HasSuffix(path, ".json") {
		return "application/json"
	}

	if strings.HasSuffix(path, ".png") {
		return "image/png"
	}

	if strings.HasSuffix(path, ".jpg") {
		return "image/jpeg"
	}

	return "application/octet-stream"
}

func serveGzippedFile(w http.ResponseWriter, r *http.Request, path string, size int64) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	acceptsGzip := false
	splitRune := func(s rune) bool { return s == ' ' || s == '\t' || s == '\n' || s == ',' }
	for _, hdr := range r.Header["Accept-Encoding"] {
		for _, enc := range strings.FieldsFunc(hdr, splitRune) {
			if enc == "gzip" {
				acceptsGzip = true
				break
			}
		}
	}

	if acceptsGzip {
		serveGzip(w, path, size)
	} else {
		serveUngzipped(w, path)
	}
}

// serveGzip serves a gzipped file with gzip content-encoding
func serveGzip(w http.ResponseWriter, path string, size int64) {
	f, err := os.Open(path)
	if err != nil {
		msg, code := toHTTPError(err)
		http.Error(w, msg, code)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))

	w.WriteHeader(http.StatusOK)
	io.Copy(w, f)
}

// serveUngzipped ungzips a gzipped file and serves it
func serveUngzipped(w http.ResponseWriter, path string) {
	f, err := os.Open(path)
	if err != nil {
		msg, code := toHTTPError(err)
		http.Error(w, msg, code)
		return
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		msg, code := toHTTPError(err)
		http.Error(w, msg, code)
		return
	}
	defer gz.Close()

	w.WriteHeader(http.StatusOK)
	io.Copy(w, gz)
}

func toHTTPError(err error) (msg string, httpStatus int) {
	if os.IsNotExist(err) {
		return "404 page not found", http.StatusNotFound
	}
	if os.IsPermission(err) {
		return "403 Forbidden", http.StatusForbidden
	}
	// Default:
	return "500 Internal Server Error", http.StatusInternalServerError
}

func containsDotDot(v string) bool {
	if !strings.Contains(v, "..") {
		return false
	}
	for _, ent := range strings.FieldsFunc(v, isSlashRune) {
		if ent == ".." {
			return true
		}
	}
	return false
}
func isSlashRune(r rune) bool { return r == '/' || r == '\\' }
