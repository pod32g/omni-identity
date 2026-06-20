package web

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

// maxLogoBytes caps an uploaded branding logo.
const maxLogoBytes = 512 * 1024

// allowedLogoTypes are the content types accepted for an uploaded logo.
var allowedLogoTypes = map[string]bool{
	"image/png":     true,
	"image/jpeg":    true,
	"image/webp":    true,
	"image/svg+xml": true,
}

// handleBrandingLogo serves the uploaded branding logo blob, or 404 if none.
func (s *Server) handleBrandingLogo(w http.ResponseWriter, r *http.Request) {
	b, err := s.db.GetBranding(r.Context())
	if err != nil || len(b.LogoBytes) == 0 {
		http.NotFound(w, r)
		return
	}
	ct := b.LogoContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(b.LogoBytes)))
	_, _ = w.Write(b.LogoBytes)
}

// handleAdminUpdateBranding saves the text branding fields.
func (s *Server) handleAdminUpdateBranding(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	productName := strings.TrimSpace(r.PostFormValue("product_name"))
	accent := strings.TrimSpace(r.PostFormValue("accent_color"))
	footer := strings.TrimSpace(r.PostFormValue("footer_text"))
	background := strings.TrimSpace(r.PostFormValue("background_style"))

	if productName == "" {
		s.renderSettings(w, r, http.StatusBadRequest, "Product name is required.", "")
		return
	}
	if accent != "" && !validCSSColor(accent) {
		s.renderSettings(w, r, http.StatusBadRequest, "Accent color must be a hex or oklch() color.", "")
		return
	}
	// background_style is rendered raw inside a <style> block; reject characters
	// that could break out of the `body { background: <value>; }` declaration.
	if strings.ContainsAny(background, "{}<>;") {
		s.renderSettings(w, r, http.StatusBadRequest, "Background style contains invalid characters.", "")
		return
	}

	b := &model.Branding{
		ProductName:     productName,
		AccentColor:     accent,
		FooterText:      footer,
		BackgroundStyle: background,
	}
	if err := s.db.UpdateBranding(r.Context(), b); err != nil {
		s.renderSettings(w, r, http.StatusInternalServerError, "Could not save branding.", "")
		return
	}
	s.branding.Reload(r.Context())
	http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
}

// handleAdminUploadLogo stores (or clears) the uploaded branding logo.
func (s *Server) handleAdminUploadLogo(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxLogoBytes + 4096); err != nil {
		s.renderSettings(w, r, http.StatusBadRequest, "Upload was too large or malformed.", "")
		return
	}
	if !auth.ValidateCSRFToken(r, r.PostFormValue("csrf_token")) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	if r.PostFormValue("action") == "remove" {
		if err := s.db.SetBrandingLogo(r.Context(), nil, ""); err != nil {
			s.renderSettings(w, r, http.StatusInternalServerError, "Could not remove logo.", "")
			return
		}
		s.branding.Reload(r.Context())
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}

	file, hdr, err := r.FormFile("logo")
	if err != nil {
		s.renderSettings(w, r, http.StatusBadRequest, "Choose an image file to upload.", "")
		return
	}
	defer file.Close()
	if hdr.Size > maxLogoBytes {
		s.renderSettings(w, r, http.StatusBadRequest, "Logo must be 512 KB or smaller.", "")
		return
	}

	buf := make([]byte, hdr.Size)
	if _, err := readFull(file, buf); err != nil {
		s.renderSettings(w, r, http.StatusBadRequest, "Could not read the uploaded file.", "")
		return
	}
	ct := detectLogoType(hdr.Header.Get("Content-Type"), buf)
	if !allowedLogoTypes[ct] {
		s.renderSettings(w, r, http.StatusBadRequest, "Logo must be a PNG, JPEG, WebP, or SVG image.", "")
		return
	}

	if err := s.db.SetBrandingLogo(r.Context(), buf, ct); err != nil {
		s.renderSettings(w, r, http.StatusInternalServerError, "Could not save logo.", "")
		return
	}
	s.branding.Reload(r.Context())
	http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
}

// cssColorRe permits hex colors and function-form colors (rgb/hsl/oklch/oklab)
// using only a safe character set, so the value cannot break out of the
// `--accent: <value>;` declaration it is rendered into.
var cssColorRe = regexp.MustCompile(`^#[0-9a-fA-F]{3,8}$|^(?:rgb|rgba|hsl|hsla|oklch|oklab)\([0-9a-zA-Z.,%/ -]+\)$`)

func validCSSColor(v string) bool {
	return cssColorRe.MatchString(v)
}

// readFull fills buf from r, erroring unless exactly len(buf) bytes are read.
func readFull(r io.Reader, buf []byte) (int, error) {
	return io.ReadFull(r, buf)
}

// detectLogoType resolves the stored content type: trust the browser-declared
// type when it is one we accept, otherwise sniff the bytes (handling SVG, which
// the stdlib sniffer does not recognize).
func detectLogoType(declared string, data []byte) string {
	declared = strings.TrimSpace(strings.SplitN(declared, ";", 2)[0])
	if allowedLogoTypes[declared] {
		return declared
	}
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("<svg")) || bytes.HasPrefix(trimmed, []byte("<?xml")) {
		return "image/svg+xml"
	}
	return http.DetectContentType(data)
}
