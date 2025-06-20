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
	"sort"
	"strconv"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/rs/zerolog"
)

// logServer is an http.handler which will serve up bugreports
type logServer struct {
	root string
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

	// reject some dodgy paths. This is based on the code for http.Dir.Open (see https://golang.org/src/net/http/fs.go#L37).
	//
	// the check for '..' is a sanity-check because my understanding of `path.Clean` is that it should never return
	// a value including '..' for input starting with '/'. It's taken from the code for http.ServeFile
	// (https://golang.org/src/net/http/fs.go#L637).
	if containsDotDot(upath) || strings.Contains(upath, "\x00") || (filepath.Separator != '/' && strings.ContainsRune(upath, filepath.Separator)) {
		http.Error(w, "invalid URL path", http.StatusBadRequest)
		return
	}

	// check if the file is in S3
	exists, err := f.checkS3FileExists(ctx, upath)
	if err != nil {
		log.Error().Err(err).Msg("Failed to check S3 file existence")
	} else if exists {
		log.Info().Msg("Serving file from S3")
		// Serve the file from S3
		http.Error(w, "S3 file serving not implemented", http.StatusNotImplemented)
		return
	}

	exists, err = f.checkLocalFileExists(ctx, upath)
	if err != nil {
		log.Error().Err(err).Msg("Failed to check local file existence")
	} else if exists {
		log.Info().Msg("Serving file from local filesystem")
		// Serve the file from the local filesystem
		http.Error(w, "Local file serving not implemented", http.StatusNotImplemented)
		return
	}

	// If we reach here, the file does not exist in S3 or locally, try to enumerate the directory
	entries, err := f.enumerateCombinedDirectory(ctx, upath)
	if err != nil {
		log.Error().Err(err).Msg("Failed to enumerate directory")
		http.Error(w, "error enumerating directory", http.StatusInternalServerError)
		return
	}
	if len(entries) == 0 {
		log.Info().Msg("Directory is empty/file not found")
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}

	log.Info().Int("entry_count", len(entries)).Msg("Serving directory listing")
	// Serve the directory listing
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("<!doctype html>\n<meta name=\"viewport\" content=\"width=device-width\">\n<pre>\n"))
	for _, entry := range entries {
		if strings.HasSuffix(entry, "/") {
			w.Write([]byte("<a href=\"" + entry + "\">" + entry + "</a>\n"))
		} else {
			w.Write([]byte("<a href=\"" + entry + "\">" + entry + "</a>\n"))
		}
	}
	w.Write([]byte("</pre>\n"))
	log.Info().Msg("Directory listing served")
}

func (f *logServer) checkS3FileExists(ctx context.Context, objectName string) (bool, error) {
	// Check if the object exists in S3
	// Remove leading slash if present
	objectName = strings.TrimPrefix(objectName, "/")
	_, err := f.s3Client.StatObject(ctx, f.s3Bucket, objectName, minio.StatObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return false, nil // Object does not exist
		}
		return false, err // Other error
	}
	return true, nil // Object exists
}

func (f *logServer) enumerateS3Directory(ctx context.Context, prefix string) ([]string, error) {
	log := zerolog.Ctx(ctx).With().Str("action", "serve_file").Logger()

	opts := minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: false,
	}
	var entries []string
	for obj := range f.s3Client.ListObjects(ctx, f.s3Bucket, opts) {
		if obj.Err != nil {
			return nil, obj.Err // Error listing S3 objects
		}
		// remove prefix from the object key
		log.Debug().Str("object_key", obj.Key).Msg("Found S3 object")
		name := strings.TrimPrefix(obj.Key, prefix)
		entries = append(entries, name)

	}
	return entries, nil
}

func (f *logServer) enumerateCombinedDirectory(ctx context.Context, prefix string) ([]string, error) {
	log := zerolog.Ctx(ctx).With().Str("action", "enumerate_combined_directory").Logger()
	// Check S3 first
	entries, err := f.enumerateS3Directory(ctx, prefix)
	if err != nil {
		return nil, err
	}

	// Now check the local filesystem
	localPath := filepath.Join(f.root, filepath.FromSlash(prefix))
	localEntries, err := os.ReadDir(localPath)
	if err != nil {
		if os.IsNotExist(err) {
			return entries, nil // No local directory, return S3 entries
		}
		return nil, err // Other error
	}

	for _, entry := range localEntries {
		log.Debug().Str("entry_name", entry.Name()).Bool("is_dir", entry.IsDir()).Msg("Found local entry")
		if entry.IsDir() {
			// If it's a directory, append it with a trailing slash
			entries = append(entries, entry.Name()+"/")
		} else {
			entries = append(entries, entry.Name())
		}
	}

	// Sort and deduplicate entries
	uniqueEntries := make(map[string]struct{})
	for _, entry := range entries {
		if _, exists := uniqueEntries[entry]; !exists {
			uniqueEntries[entry] = struct{}{}
		}
	}
	uniqueEntriesSlice := make([]string, 0, len(uniqueEntries))
	for entry := range uniqueEntries {
		uniqueEntriesSlice = append(uniqueEntriesSlice, entry)
	}
	sort.Strings(uniqueEntriesSlice)
	return uniqueEntriesSlice, nil
}

func (f *logServer) checkLocalFileExists(ctx context.Context, path string) (bool, error) {
	log := zerolog.Ctx(ctx).With().Str("action", "check_local_file_exists").Logger()
	// Convert to absolute path
	absPath, err := filepath.Abs(filepath.Join(f.root, filepath.FromSlash(path)))
	if err != nil {
		return false, err
	}

	// Check if the file exists
	entry, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil // File does not exist
		}
		return false, err // Other error
	}
	if entry.IsDir() {
		log.Warn().Str("file_path", absPath).Msg("Expected file but found a directory")
		return false, nil // It's a directory, not a file
	}
	log.Debug().Str("file_path", absPath).Msg("Local file exists")
	return true, nil // File exists
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
