//go:build !android

package web

import (
	"embed"
	"net/http"
	"strconv"
)

//go:embed ui/*
var uiFS embed.FS

type staticFile struct {
	ctype string
	data  []byte
}

// static maps request paths to embedded files. "/" and "/index.html" are
// special: index.html with a session, login.html without (§13.4).
var static = func() map[string]staticFile {
	types := map[string]string{
		"index.html": "text/html; charset=utf-8",
		"login.html": "text/html; charset=utf-8",
		"app.js":     "text/javascript; charset=utf-8",
		"app.css":    "text/css; charset=utf-8",
		"icons.svg":  "image/svg+xml",
	}
	m := map[string]staticFile{}
	for name, ct := range types {
		b, err := uiFS.ReadFile("ui/" + name)
		if err != nil {
			panic("web: missing embedded ui/" + name)
		}
		m["/"+name] = staticFile{ctype: ct, data: b}
	}
	return m
}()

func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	if !isSafeMethod(r.Method) {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := r.URL.Path
	if p == "/" || p == "/index.html" {
		if _, ok := s.auth.lookup(r, s.now()); ok {
			p = "/index.html"
		} else {
			p = "/login.html"
		}
	}
	f, ok := static[p]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", f.ctype)
	w.Header().Set("Content-Length", strconv.Itoa(len(f.data)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(f.data)
	}
}
