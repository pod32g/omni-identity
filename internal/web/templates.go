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
	// brand supplies the current branding to the `brand` template function. It
	// is read at render time, so the Server can swap it in after construction.
	brand func() BrandingView
}

// loadTemplates parses every page template (any templates/*.html except
// base.html) together with the base layout. The `brand` template function lets
// every page render branding without threading it through each page struct.
func loadTemplates() (*templates, error) {
	entries, err := fs.ReadDir(templateFS, "templates")
	if err != nil {
		return nil, err
	}
	t := &templates{set: map[string]*template.Template{}, brand: defaultBranding}
	funcs := template.FuncMap{
		"brand": func() BrandingView { return t.brand() },
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == "base.html" || !strings.HasSuffix(name, ".html") {
			continue
		}
		tmpl, err := template.New("base.html").Funcs(funcs).ParseFS(
			templateFS, "templates/base.html", "templates/"+name)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		t.set[strings.TrimSuffix(name, ".html")] = tmpl
	}
	return t, nil
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
