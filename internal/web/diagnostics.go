package web

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

// Device diagnostics: an enrolled device may upload a plain-text log bundle
// authenticated by its device token (DPoP-bound, like every device API
// call). Files are kept per device on disk, the most recent ten, and shown
// to administrators on the device's page. Nothing is parsed or executed;
// the content is opaque text and never rendered as HTML.

const (
	maxDiagnosticsBytes = 256 * 1024
	keepDiagnostics     = 10
)

var diagName = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z\.log$`)

type diagFile struct {
	Name     string
	Size     int64
	Modified time.Time
}

func (s *Server) diagnosticsEnabled() bool { return s.cfg.Diagnostics.Dir != "" }

func (s *Server) diagnosticsDir(deviceID string) string {
	return filepath.Join(s.cfg.Diagnostics.Dir, filepath.Base(deviceID))
}

// handleDeviceDiagnosticsUpload stores the body as the device's newest log.
func (s *Server) handleDeviceDiagnosticsUpload(w http.ResponseWriter, r *http.Request, dev *model.Device) {
	if !s.diagnosticsEnabled() {
		apiError(w, http.StatusNotFound, "not_supported", "diagnostics uploads are disabled on this server")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDiagnosticsBytes+1))
	if err != nil || len(body) > maxDiagnosticsBytes {
		apiError(w, http.StatusRequestEntityTooLarge, "too_large", "diagnostics are limited to 256 KiB")
		return
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		apiError(w, http.StatusBadRequest, "invalid_request", "empty body")
		return
	}
	dir := s.diagnosticsDir(dev.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		apiError(w, http.StatusInternalServerError, "storage", "cannot store diagnostics")
		return
	}
	name := time.Now().UTC().Format("20060102T150405Z") + ".log"
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
		apiError(w, http.StatusInternalServerError, "storage", "cannot store diagnostics")
		return
	}
	pruneDiagnostics(dir)
	s.audit(r, evtDeviceDiagnostics, auditEntry{actorUserID: dev.OwnerUserID, success: true, detail: "device=" + dev.ID + " file=" + name})
	writeJSON(w, http.StatusOK, map[string]any{"stored": name, "bytes": len(body)})
}

func pruneDiagnostics(dir string) {
	files := listDiagnostics(dir)
	for i := keepDiagnostics; i < len(files); i++ {
		_ = os.Remove(filepath.Join(dir, files[i].Name))
	}
}

// listDiagnostics returns the device's uploads, newest first.
func listDiagnostics(dir string) []diagFile {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []diagFile
	for _, e := range entries {
		if !e.Type().IsRegular() || !diagName.MatchString(e.Name()) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, diagFile{Name: e.Name(), Size: fi.Size(), Modified: fi.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out
}

// handleAdminDeviceDiagnostic serves one upload as plain text to an admin.
func (s *Server) handleAdminDeviceDiagnostic(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !s.diagnosticsEnabled() || !diagName.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	dev, err := s.db.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil || dev == nil {
		http.NotFound(w, r)
		return
	}
	raw, err := os.ReadFile(filepath.Join(s.diagnosticsDir(dev.ID), name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "cannot read", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}
