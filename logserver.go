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
	
	log.Info().Msg("Serving report logs")
	
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
		r.URL.Path = upath
	}

	// eliminate ., .., //, etc
	upath = path.Clean(upath)

	// remove the leading slash, will turn root into ""
	upath = strings.TrimPrefix(upath, "/")

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
		// get a reader for the S3 object
		obj, err := f.s3Client.GetObject(ctx, f.s3Bucket, upath, minio.GetObjectOptions{})
		if err != nil {
			log.Error().Err(err).Msg("Failed to get S3 object")
			http.Error(w, "error retrieving S3 object", http.StatusInternalServerError)
			return
		}
		defer obj.Close()
		// serve the file
		serveFile(ctx, w, r, upath, obj)
		return
	}

	// check if file is on local disk (for migration)
	exists, err = f.checkLocalFileExists(ctx, upath)
	if err != nil {
		log.Error().Err(err).Msg("Failed to check local file existence")
	} else if exists {
		log.Info().Msg("Serving file from local filesystem")
		// open the file on the local filesystem
		localPath, err := filepath.Abs(filepath.Join(f.root, filepath.FromSlash(upath)))
		if err != nil {
			log.Error().Err(err).Msg("Failed to get absolute path for local file")
			http.Error(w, "error retrieving local file", http.StatusInternalServerError)
		}
		f, err := os.Open(localPath)
		if err != nil {
			log.Error().Err(err).Msg("Failed to open local file")
			http.Error(w, "error opening local file", http.StatusInternalServerError)
		}
		defer f.Close()
		// serve the file
		serveFile(ctx, w, r, upath, f)
		return
	}

	// try to enumerate as a directory
	entries, err := f.enumerateCombinedDirectory(ctx, upath)
	if err != nil {
		log.Error().Err(err).Msg("Failed to enumerate directory")
		http.Error(w, "error enumerating directory", http.StatusInternalServerError)
		return
	}
	if len(entries) == 0 {
		log.Info().Msg("Directory is empty/file not found")
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}

	log.Info().Int("entry_count", len(entries)).Msg("Serving directory listing")
	// serve the directory listing
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("<!doctype html>\n<meta name=\"viewport\" content=\"width=device-width\">\n<pre>\n"))
	for _, entry := range entries {
		w.Write([]byte("<a href=\"" + entry + "\">" + entry + "</a>\n"))
	}
	w.Write([]byte("</pre>\n"))
}

func (f *logServer) checkS3FileExists(ctx context.Context, objectName string) (bool, error) {
	_, err := f.s3Client.StatObject(ctx, f.s3Bucket, objectName, minio.StatObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// returns contents of a "directory" in the form FolderName/
func (f *logServer) enumerateS3Directory(ctx context.Context, prefix string) ([]string, error) {
	log := zerolog.Ctx(ctx).With().Str("action", "serve_file").Logger()

	log.Debug().Str("s3_bucket", f.s3Bucket).Str("prefix", prefix).Msg("Enumerating S3 directory")

	// add a trailing slash to prevent partial matches (e.g. "2025-" matching "2025-01-01/" and "2025-01-02/")
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
			return nil, obj.Err
		}
		// trim prefix and leading /, leaving just FolderName/FileName or FileName
		name := strings.TrimPrefix(obj.Key, prefix)
		// ignore directory entry
		if name == "" {
			continue
		}
		// If it's a subdirectory, only show the first segment
		if idx := strings.IndexRune(name, '/'); idx != -1 {
			name = name[:idx+1]
		}
		entries = append(entries, name)
	}
	return entries, nil
}

func (f *logServer) enumerateCombinedDirectory(ctx context.Context, prefix string) ([]string, error) {
	log := zerolog.Ctx(ctx).With().Str("action", "enumerate_combined_directory").Logger()
	// check S3 first
	entries, err := f.enumerateS3Directory(ctx, prefix)
	if err != nil {
		return nil, err
	}

	// now check the local filesystem
	localPath, err := filepath.Abs(filepath.Join(f.root, filepath.FromSlash(prefix)))
	if err != nil {
		log.Error().Err(err).Msg("Failed to get absolute path for local directory")
		return nil, err
	}
	localEntries, err := os.ReadDir(localPath)
	if err != nil {
		if os.IsNotExist(err) {
			return entries, nil // no local directory, return any S3 entries
		}
		return nil, err
	}

	for _, entry := range localEntries {
		log.Debug().Str("entry_name", entry.Name()).Bool("is_dir", entry.IsDir()).Msg("Found local entry")
		if entry.IsDir() {
			// if it's a directory, append it with a trailing slash
			entries = append(entries, entry.Name()+"/")
		} else {
			entries = append(entries, entry.Name())
		}
	}

	// sort and deduplicate entries
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

// check if a file exists in f.root, ignoring directories
func (f *logServer) checkLocalFileExists(ctx context.Context, path string) (bool, error) {
	// convert to absolute path (probably just adding /)
	absPath, err := filepath.Abs(filepath.Join(f.root, filepath.FromSlash(path)))
	if err != nil {
		return false, err
	}

	// check if the file exists
	entry, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if entry.IsDir() {
		return false, nil
	}
	return true, nil
}

func serveFile(ctx context.Context, w http.ResponseWriter, r *http.Request, filename string, reader io.Reader) {
	log := zerolog.Ctx(ctx).With().Str("action", "serve_file").Logger()

	// for anti-XSS belt-and-braces, set a very restrictive CSP
	w.Header().Set("Content-Security-Policy", "default-src: none")

	// if it is gzipped, check if the client accepts gzip encoding
	if strings.HasSuffix(filename, ".gz") {
		log.Debug().Msg("Serving gzipped file")
		if acceptsGzip(r) {
			// set the content-encoding to gzip
			w.Header().Set("Content-Encoding", "gzip")
		} else {
			var err error
			reader, err = gzip.NewReader(reader)
			if err != nil {
				log.Error().Err(err).Msg("Failed to create gzip reader")
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
		}
		filename = strings.TrimSuffix(filename, ".gz")
	}

	// set the content-type based on the file extension
	// otherwise, limit ourselves to a number of known-safe content-types, to
	// guard against XSS vulnerabilities.
	w.Header().Set("Content-Type", extensionToMimeType(filename))

	// read everything from the reader and write it to the response
	log.Debug().Str("filename", filename).Msg("Serving file")
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Content-Length", strconv.FormatInt(-1, 10)) // -1 means unknown length
	if _, err := io.Copy(w, reader); err != nil {
		log.Error().Err(err).Msg("Failed to copy file content to response")
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	log.Debug().Msg("File served successfully")
	w.WriteHeader(http.StatusOK)
}

// extensionToMimeType returns a suitable mime type for the given filename
//
// Unlike mime.TypeByExtension, the results are limited to a set of types which
// should be safe to serve to a browser without introducing XSS vulnerabilities.
func extensionToMimeType(path string) string {
	if strings.HasSuffix(path, ".txt") || strings.HasSuffix(path, ".log"){
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

func acceptsGzip(r *http.Request) bool {
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
	return acceptsGzip
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
