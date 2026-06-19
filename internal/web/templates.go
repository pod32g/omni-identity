package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

// templates holds one parsed template set per page, each composed with the
// shared base layout.
type templates struct {
	set map[string]*template.Template
}

// loadTemplates parses every page template (any templates/*.html except
// base.html) together with the base layout.
func loadTemplates() (*templates, error) {
	entries, err := fs.ReadDir(templateFS, "templates")
	if err != nil {
		return nil, err
	}
	set := map[string]*template.Template{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == "base.html" || !strings.HasSuffix(name, ".html") {
			continue
		}
		t, err := template.New("base.html").ParseFS(
			templateFS, "templates/base.html", "templates/"+name)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		set[strings.TrimSuffix(name, ".html")] = t
	}
	return &templates{set: set}, nil
}

// render writes the named page to w with the given status code and data.
func (t *templates) render(w http.ResponseWriter, status int, name string, data any) {
	tmpl, ok := t.set[name]
	if !ok {
		http.Error(w, "template not found: "+name, http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "base.html", data); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}
