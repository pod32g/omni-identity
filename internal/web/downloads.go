package web

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

// Endpoint artifact downloads. The Docker build cross-compiles the
// omni-enrollment agent (and tars the PAM/systemd sources) into /downloads at
// the same commit as the server; the "Enroll a device" page lists them with
// SHA-256 checksums so a user can install a version-matched agent without a
// separate release pipeline. Only regular files directly inside the
// configured directory are ever served, by base name.

// artifact is one downloadable file.
type artifact struct {
	Name     string
	Label    string // human description
	Size     string
	SHA256   string
	Modified time.Time
}

var artifactLabels = map[string]string{
	"omni-enrollment-linux-amd64":       "Linux agent, x86-64",
	"omni-enrollment-linux-arm64":       "Linux agent, arm64 (Raspberry Pi, Apple-silicon VMs)",
	"omni-enrollment-windows-amd64.exe": "Windows agent, x86-64 (used by the Omni Access desktop client)",
	"omni-enrollment-endpoint.tar.gz":   "PAM module and systemd unit sources",
	"omni-access-windows-amd64.zip":     "Omni Access for Windows, pre-configured for this server (one file, agent included), x86-64",
	"omni-access-macos-arm64.zip":       "Omni Access for macOS, Apple silicon",
}

// downloadsService lists and checksums the artifacts, caching by mtime.
// Artifacts come from the image's own directory and, optionally, an extra
// directory for files built elsewhere (for example the Omni Access desktop
// clients, dropped there by that project's deployment); the image's copy
// wins when both hold the same name.
type downloadsService struct {
	dir   string
	extra string
	mu    sync.Mutex
	cache map[string]artifact
}

func newDownloadsService(dir, extra string) *downloadsService {
	return &downloadsService{dir: dir, extra: extra, cache: map[string]artifact{}}
}

// Enabled reports whether a downloads directory is configured.
func (d *downloadsService) Enabled() bool { return d != nil && (d.dir != "" || d.extra != "") }

// path resolves a base name to the file to serve, or "" when absent.
func (d *downloadsService) path(name string) string {
	if name == "" || name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		return ""
	}
	for _, dir := range []string{d.dir, d.extra} {
		if dir == "" {
			continue
		}
		if fi, err := os.Stat(filepath.Join(dir, name)); err == nil && fi.Mode().IsRegular() {
			return filepath.Join(dir, name)
		}
	}
	return ""
}

// List returns the artifacts sorted by name (labelled ones first).
func (d *downloadsService) List() []artifact {
	if !d.Enabled() {
		return nil
	}
	seen := map[string]bool{}
	var out []artifact
	for _, dir := range []string{d.dir, d.extra} {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.Type().IsRegular() || strings.HasPrefix(e.Name(), ".") || seen[e.Name()] {
				continue
			}
			if a, ok := d.describe(e.Name()); ok {
				seen[e.Name()] = true
				out = append(out, a)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		li, lj := artifactLabels[out[i].Name] != "", artifactLabels[out[j].Name] != ""
		if li != lj {
			return li
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// describe stats and (when needed) re-hashes one artifact.
func (d *downloadsService) describe(name string) (artifact, bool) {
	full := d.path(name)
	if full == "" {
		return artifact{}, false
	}
	fi, err := os.Stat(full)
	if err != nil {
		return artifact{}, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if a, ok := d.cache[name]; ok && a.Modified.Equal(fi.ModTime()) {
		return a, true
	}
	f, err := os.Open(full)
	if err != nil {
		return artifact{}, false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return artifact{}, false
	}
	a := artifact{
		Name:     name,
		Label:    artifactLabels[name],
		Size:     humanSize(fi.Size()),
		SHA256:   hex.EncodeToString(h.Sum(nil)),
		Modified: fi.ModTime(),
	}
	if a.Label == "" {
		a.Label = name
	}
	d.cache[name] = a
	return a, true
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// handleDownload serves one artifact by base name. Public: the agent is open
// source and the page shows checksums; nothing here is secret.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !s.downloads.Enabled() || name == "" || name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		http.NotFound(w, r)
		return
	}
	a, ok := s.downloads.describe(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	full := s.downloads.path(name)
	if full == "" {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(full)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Checksum-SHA256", a.SHA256)
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, name, a.Modified, f)
}

// --- Enroll a device page ---

type enrollPage struct {
	CSRFToken string
	Me        *model.User
	Active    string
	Issuer    string
	Artifacts []artifact
	Enabled   bool
	Insecure  bool // issuer is http://: the agent needs --allow-insecure-http
}

func (s *Server) handleAccountEnroll(w http.ResponseWriter, r *http.Request) {
	issuer := s.settings.Current().Issuer
	s.tmpl.render(w, http.StatusOK, "account_enroll", enrollPage{
		CSRFToken: auth.CSRFToken(w, r, s.cookieSecure()),
		Me:        currentUser(r),
		Active:    "account",
		Issuer:    issuer,
		Artifacts: s.downloads.List(),
		Enabled:   s.downloads.Enabled(),
		Insecure:  strings.HasPrefix(issuer, "http://"),
	})
}
