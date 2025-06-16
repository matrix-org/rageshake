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
	"fmt"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/rs/zerolog"
)

// logServer is an http.handler which will serve up bugreports
type logServer struct {
	s3Client *minio.Client
	s3Bucket string
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

	// reject some dodgy paths
	if containsDotDot(upath) || strings.Contains(upath, "\x00") || (filepath.Separator != '/' && strings.ContainsRune(upath, filepath.Separator)) {
		http.Error(w, "invalid URL path", http.StatusBadRequest)
		return
	}
	objectName := strings.TrimPrefix(upath, "/")

	// Directory listing (unchanged)
	if strings.HasSuffix(r.URL.Path, "/") || objectName == "" {
		// List S3 objects with this prefix
		prefix := objectName
		if prefix != "" && !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		var entries []string
		opts := minio.ListObjectsOptions{
			Prefix:    prefix,
			Recursive: false,
		}
		for obj := range f.s3Client.ListObjects(ctx, f.s3Bucket, opts) {
			if obj.Err != nil {
				log.Err(obj.Err).Msg("Error listing S3 objects")
				http.Error(w, "error listing directory", http.StatusInternalServerError)
				return
			}
			name := strings.TrimPrefix(obj.Key, prefix)
			// Only show direct children
			if name == "" {
				continue
			}
			// If it's a subdirectory, only show the first segment
			if idx := strings.IndexRune(name, '/'); idx != -1 {
				name = name[:idx+1]
			}
			// Avoid duplicates
			found := false
			for _, e := range entries {
				if e == name {
					found = true
					break
				}
			}
			if !found {
				entries = append(entries, name)
			}
		}
		// Sort entries
		// Optionally: sort.Strings(entries)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body><h1>Listing for /%s</h1><ul>", htmlEscape(prefix))
		parent := path.Dir("/" + prefix)
		if parent != "/" && parent != "." {
			fmt.Fprintf(w, `<li><a href="%s/">../</a></li>`, htmlEscape(parent))
		}
		for _, e := range entries {
			link := e
			if strings.HasSuffix(e, "/") {
				fmt.Fprintf(w, `<li><a href="%s">%s</a></li>`, htmlEscape(e), htmlEscape(e))
			} else {
				fmt.Fprintf(w, `<li><a href="%s">%s</a></li>`, htmlEscape(link), htmlEscape(e))
			}
		}
		fmt.Fprint(w, "</ul></body></html>")
		return
	}

	// Otherwise, serve the file from S3
	obj, err := f.s3Client.GetObject(ctx, f.s3Bucket, objectName, minio.GetObjectOptions{})
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	defer obj.Close()
	stat, err := obj.Stat()
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Security-Policy", "default-src: none")
	w.Header().Set("Content-Type", extensionToMimeType(objectName))

	if strings.HasSuffix(objectName, ".gz") {
		serveS3GzippedFile(w, r, obj, stat.Size)
	} else {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size))
		w.WriteHeader(http.StatusOK)
		io.Copy(w, obj)
	}
}

// Serve a .gz file from S3, decompressing if needed
func serveS3GzippedFile(w http.ResponseWriter, r *http.Request, obj *minio.Object, size int64) {
	acceptsGzip := clientAcceptsGzip(r)
	if acceptsGzip {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
		w.WriteHeader(http.StatusOK)
		io.Copy(w, obj)
	} else {
		serveS3Ungzipped(w, obj)
	}
}

// Serve a .gz file from S3, decompressing on the fly
func serveS3Ungzipped(w http.ResponseWriter, obj *minio.Object) {
	gz, err := gzip.NewReader(obj)
	if err != nil {
		http.Error(w, "failed to decompress", http.StatusInternalServerError)
		return
	}
	defer gz.Close()
	w.WriteHeader(http.StatusOK)
	io.Copy(w, gz)
}

// Utility: check if client accepts gzip
func clientAcceptsGzip(r *http.Request) bool {
	splitRune := func(s rune) bool { return s == ' ' || s == '\t' || s == '\n' || s == ',' }
	for _, hdr := range r.Header["Accept-Encoding"] {
		for _, enc := range strings.FieldsFunc(hdr, splitRune) {
			if enc == "gzip" {
				return true
			}
		}
	}
	return false
}

func htmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
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
