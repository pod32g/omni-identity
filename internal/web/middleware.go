package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// statusRecorder captures the response status code for logging and metrics.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.written {
		s.status = code
		s.written = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.written {
		s.status = http.StatusOK
		s.written = true
	}
	return s.ResponseWriter.Write(b)
}

// metrics holds simple in-memory request counters.
type metrics struct {
	mu       sync.Mutex
	total    int64
	byStatus map[int]int64
}

func newMetrics() *metrics {
	return &metrics{byStatus: map[int]int64{}}
}

func (m *metrics) record(status int) {
	m.mu.Lock()
	m.total++
	m.byStatus[status]++
	m.mu.Unlock()
}

func (m *metrics) render() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var b strings.Builder
	b.WriteString("# HELP omni_identity_http_requests_total Total HTTP requests handled.\n")
	b.WriteString("# TYPE omni_identity_http_requests_total counter\n")
	fmt.Fprintf(&b, "omni_identity_http_requests_total %d\n", m.total)
	b.WriteString("# HELP omni_identity_http_requests_by_status Requests by HTTP status.\n")
	b.WriteString("# TYPE omni_identity_http_requests_by_status counter\n")

	statuses := make([]int, 0, len(m.byStatus))
	for s := range m.byStatus {
		statuses = append(statuses, s)
	}
	sort.Ints(statuses)
	for _, s := range statuses {
		fmt.Fprintf(&b, "omni_identity_http_requests_by_status{status=\"%d\"} %d\n", s, m.byStatus[s])
	}
	return b.String()
}

// withMiddleware wraps the router with logging, recovery, and security headers.
// logging is outermost so it observes the final status, including 500s written
// by the recoverer.
func (s *Server) withMiddleware(h http.Handler) http.Handler {
	return s.logging(s.recoverer(s.securityHeaders(h)))
}

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		s.metrics.record(rec.status)
		if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
			return // avoid log noise from probes/scrapers
		}
		slog.Info("http_request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered", "error", rec, "path", r.URL.Path)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// img-src allows https so the hosted login can show a registered client's
		// externally hosted logo; the uploaded Omni logo is served from 'self'.
		h.Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' https: data:; frame-ancestors 'none'")
		// HSTS only when serving over HTTPS (secure cookies imply TLS).
		if s.cfg.Cookies.Secure {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(s.metrics.render()))
}
