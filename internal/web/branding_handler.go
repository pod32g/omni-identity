package web

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

// defaultMaxLogoBytes caps uploaded branding logos unless changed in settings.
const defaultMaxLogoBytes = 512 * 1024

// allowedLogoTypes are the content types accepted for an uploaded logo.
var allowedLogoTypes = map[string]bool{
	"image/png":  true,
	"image/jpeg": true,
	"image/webp": true,
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
	s.audit(r, evtBrandingUpdate, auditEntry{actorUserID: actorID(r), success: true})
	http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
}

// handleAdminUploadLogo stores (or clears) the uploaded branding logo.
func (s *Server) handleAdminUploadLogo(w http.ResponseWriter, r *http.Request) {
	maxLogoBytes := s.settings.Current().MaxLogoBytes
	if maxLogoBytes < 1 {
		maxLogoBytes = defaultMaxLogoBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxLogoBytes)+32*1024)
	if err := r.ParseMultipartForm(int64(maxLogoBytes) + 4096); err != nil {
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
	if hdr.Size > int64(maxLogoBytes) {
		s.renderSettings(w, r, http.StatusBadRequest, "Logo must be "+formatBytes(maxLogoBytes)+" or smaller.", "")
		return
	}

	buf, err := io.ReadAll(io.LimitReader(file, int64(maxLogoBytes)+1))
	if err != nil {
		s.renderSettings(w, r, http.StatusBadRequest, "Could not read the uploaded file.", "")
		return
	}
	if len(buf) > maxLogoBytes {
		s.renderSettings(w, r, http.StatusBadRequest, "Logo must be "+formatBytes(maxLogoBytes)+" or smaller.", "")
		return
	}
	ct := detectLogoType(hdr.Header.Get("Content-Type"), buf)
	if !allowedLogoTypes[ct] {
		s.renderSettings(w, r, http.StatusBadRequest, "Logo must be a PNG, JPEG, or WebP image.", "")
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

// detectLogoType resolves the stored content type: trust an accepted
// browser-declared raster type, otherwise sniff the bytes.
func detectLogoType(declared string, data []byte) string {
	declared = strings.TrimSpace(strings.SplitN(declared, ";", 2)[0])
	if allowedLogoTypes[declared] {
		return declared
	}
	return http.DetectContentType(data)
}

func formatBytes(n int) string {
	if n%1024 == 0 {
		return fmt.Sprintf("%d KiB", n/1024)
	}
	return fmt.Sprintf("%d bytes", n)
}
