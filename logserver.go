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
	"archive/tar"
	"compress/gzip"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// logServer is an http.handler which will serve up bugreports
type logServer struct {
	root string
}

func (f *logServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upath := r.URL.Path

	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
		r.URL.Path = upath
	}

	log.Println("Serving", upath)

	// eliminate ., .., //, etc
	upath = path.Clean(upath)

	// reject some dodgy paths. This is based on the code for http.Dir.Open (see https://golang.org/src/net/http/fs.go#L37).
	//
	// the check for '..' is a sanity-check because my understanding of `path.Clean` is that it should never return
	// a value including '..' for input starting with '/'. It's taken from the code for http.ServeFile
	// (https://golang.org/src/net/http/fs.go#L637).
	if containsDotDot(upath) || strings.Contains(upath, "\x00") || (filepath.Separator != '/' && strings.IndexRune(upath, filepath.Separator) >= 0) {
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

	serveFile(w, r, upath)
}

func serveFile(w http.ResponseWriter, r *http.Request, path string) {
	d, err := os.Stat(path)
	if err != nil {
		msg, code := toHTTPError(err)
		http.Error(w, msg, code)
		return
	}

	// for anti-XSS belt-and-braces, set a very restrictive CSP
	w.Header().Set("Content-Security-Policy", "default-src: none")

	// if it's a directory, serve a listing or a tarball
	if d.IsDir() {
		serveDirectory(w, r, path)
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
// These match file file extensions we allow on upload, plus 'log' which we do
// not allow to be submitted but we use as the extension when logs are submitted
// (eg. 'compressed-log' entries are saved to .log.gz).
func extensionToMimeType(path string) string {
	if strings.HasSuffix(path, ".txt") || strings.HasSuffix(path, ".log") {
		// anyone uploading text in anything other than utf-8 needs to be
		// re-educated.
		return "text/plain; charset=utf-8"
	}

	if strings.HasSuffix(path, ".png") {
		return "image/png"
	}

	if strings.HasSuffix(path, ".jpg") {
		return "image/jpeg"
	}

	if strings.HasSuffix(path, ".json") {
		return "application/json"
	}
	return "application/octet-stream"
}

// Chooses to serve either a directory listing or tarball based on the 'format' parameter.
func serveDirectory(w http.ResponseWriter, r *http.Request, path string) {
	format, _ := r.URL.Query()["format"]
	if len(format) == 1 && format[0] == "tar.gz" {
		log.Println("Serving tarball of", path)
		err := serveTarball(w, r, path)
		if err != nil {
			msg, code := toHTTPError(err)
			http.Error(w, msg, code)
			log.Println("Error", err)
		}
		return
	}
	log.Println("Serving directory listing of", path)
	http.ServeFile(w, r, path)
}

// Streams a dynamically created tar.gz file with the contents of the given directory
// Will serve a partial, corrupted response if there is a error partway through the
// operation as we stream the response.
//
// The resultant tarball will contain a single directory containing all the files
// so it can unpack cleanly without overwriting other files.
//
// Errors are only returned if generated before the tarball has started being
// written to the ResponseWriter
func serveTarball(w http.ResponseWriter, r *http.Request, dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}

	// Creates a "disposition filename"
	// Take a URL.path like `/2022-01-10/184843-BZZXEGYH/`
	// and removes leading and trailing `/` and replaces internal `/` with `_`
	// to form a suitable filename for use in the content-disposition header
	// dfilename would turn into `2022-01-10_184843-BZZXEGYH`
	dfilename := strings.Trim(r.URL.Path, "/")
	dfilename = strings.Replace(dfilename, "/", "_", -1)

	// There is no application/tgz or similar; return a gzip file as best option.
	// This tends to trigger archive type tools, which will then use the filename to
	// identify the contents correctly.
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename="+dfilename+".tar.gz")

	files, err := directory.Readdir(-1)
	if err != nil {
		return err
	}

	gzip := gzip.NewWriter(w)
	defer gzip.Close()
	targz := tar.NewWriter(gzip)
	defer targz.Close()

	for _, file := range files {
		if file.IsDir() {
			// We avoid including nested directories
			// This will result in requests for directories with only directories in
			// to return an empty tarball instead of recursively including directories.
			// This helps the server remain performant as a download of 'everything' would be slow
			continue
		}
		path := dir + "/" + file.Name()
		// We use the existing disposition filename to create a base directory structure for the files
		// so when they are unpacked, they are grouped in a unique folder on disk
		err := addToArchive(targz, dfilename, path)
		if err != nil {
			// From this point we assume that data may have been sent to the client already.
			// We therefore do not http.Error() after this point, instead closing the stream and
			// allowing the client to deal with a partial file as if there was a network issue.
			log.Println("Error streaming tarball", err)
			return nil
		}
	}
	return nil
}

// Add a single file into the archive.
func addToArchive(targz *tar.Writer, dfilename string, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return err
	}
	header.Name = dfilename + "/" + info.Name()

	err = targz.WriteHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(targz, file)
	if err != nil {
		return err
	}
	return nil
}

func serveGzippedFile(w http.ResponseWriter, r *http.Request, path string, size int64) {
	cType := "text/plain; charset=utf-8"
	if strings.HasSuffix(path, ".gz") {
		// Guess the mime type from the extension as we do in serveFile, but without
		// the .gz header (in practice, either plain text or application/json).
		cType = extensionToMimeType(path[:len(path)-len(".gz")])
	}
	w.Header().Set("Content-Type", cType)

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
		serveGzip(w, r, path, size)
	} else {
		serveUngzipped(w, r, path)
	}
}

// serveGzip serves a gzipped file with gzip content-encoding
func serveGzip(w http.ResponseWriter, r *http.Request, path string, size int64) {
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
func serveUngzipped(w http.ResponseWriter, r *http.Request, path string) {
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
