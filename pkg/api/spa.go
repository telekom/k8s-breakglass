// Source: https://github.com/mandrigin/gin-spa
//
// MIT License
//
// Copyright (c) 2020 Igor Mandrigin
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package api

import (
	"net/http"
	"strings"

	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
)

// cacheControlWriter wraps http.ResponseWriter to set Cache-Control headers
// based on the request path before writing the response.
type cacheControlWriter struct {
	http.ResponseWriter
	path        string
	wroteHeader bool
}

func (w *cacheControlWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		// Set cache headers based on file type
		// Vite builds produce hashed filenames for JS/CSS, so they can be cached long-term
		// index.html and other non-hashed files should not be cached
		if strings.HasPrefix(w.path, "/assets/") {
			// Hashed assets in /assets/ can be cached for 1 year (immutable)
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else if strings.HasSuffix(w.path, ".html") || w.path == "/" {
			// HTML files should always be revalidated to get latest app version
			w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		} else {
			// Other static files (fonts, images without hashes) - cache with revalidation
			w.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
		}
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *cacheControlWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func ServeSPA(urlPrefix, spaDirectory string) gin.HandlerFunc {
	directory := static.LocalFile(spaDirectory, true)
	fileserver := http.FileServer(directory)
	if urlPrefix != "" {
		fileserver = http.StripPrefix(urlPrefix, fileserver)
	}
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if directory.Exists(urlPrefix, path) {
			// Wrap the response writer to set cache headers
			ccWriter := &cacheControlWriter{ResponseWriter: c.Writer, path: path}
			fileserver.ServeHTTP(ccWriter, c.Request)
			c.Abort()
		} else {
			// SPA fallback to index.html - always revalidate
			c.Request.URL.Path = "/"
			ccWriter := &cacheControlWriter{ResponseWriter: c.Writer, path: "/"}
			fileserver.ServeHTTP(ccWriter, c.Request)
			c.Abort()
		}
	}
}
