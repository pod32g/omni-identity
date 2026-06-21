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

// BuildVersion is the binary version surfaced as omni_identity_build_info on
// /metrics. main sets it at startup; tests and the zero value fall back to "dev".
var BuildVersion = "dev"

// metrics holds in-memory counters exposed at /metrics in Prometheus text format.
// It is hand-rolled (no client library) to match the project's single-binary,
// dependency-light style.
type metrics struct {
	mu       sync.Mutex
	total    int64
	byStatus map[int]int64
	logins   map[[2]string]int64 // {source, result} → count
	mfa      map[string]int64    // result → count
	tokens   map[string]int64    // token type → count
}

func newMetrics() *metrics {
	return &metrics{
		byStatus: map[int]int64{},
		logins:   map[[2]string]int64{},
		mfa:      map[string]int64{},
		tokens:   map[string]int64{},
	}
}

func (m *metrics) record(status int) {
	m.mu.Lock()
	m.total++
	m.byStatus[status]++
	m.mu.Unlock()
}

// recordLogin counts a login attempt outcome. source ∈ {local, ldap, unknown},
// result ∈ {success, failure}.
func (m *metrics) recordLogin(source, result string) {
	m.mu.Lock()
	m.logins[[2]string{source, result}]++
	m.mu.Unlock()
}

// recordMFA counts a second-factor event. result ∈ {challenge, success, failure}.
func (m *metrics) recordMFA(result string) {
	m.mu.Lock()
	m.mfa[result]++
	m.mu.Unlock()
}

// recordToken counts an issued token by type ∈ {access, id, refresh}.
func (m *metrics) recordToken(typ string) {
	m.mu.Lock()
	m.tokens[typ]++
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

	b.WriteString("# HELP omni_identity_logins_total Login attempts by source and result.\n")
	b.WriteString("# TYPE omni_identity_logins_total counter\n")
	loginKeys := make([][2]string, 0, len(m.logins))
	for k := range m.logins {
		loginKeys = append(loginKeys, k)
	}
	sort.Slice(loginKeys, func(i, j int) bool {
		if loginKeys[i][0] != loginKeys[j][0] {
			return loginKeys[i][0] < loginKeys[j][0]
		}
		return loginKeys[i][1] < loginKeys[j][1]
	})
	for _, k := range loginKeys {
		fmt.Fprintf(&b, "omni_identity_logins_total{source=%q,result=%q} %d\n", k[0], k[1], m.logins[k])
	}

	writeLabeled(&b, "omni_identity_mfa_total", "MFA events by result.", "result", m.mfa)
	writeLabeled(&b, "omni_identity_tokens_issued_total", "Tokens issued by type.", "type", m.tokens)
	return b.String()
}

// writeLabeled renders a single-label counter family with sorted label values.
func writeLabeled(b *strings.Builder, name, help, label string, vals map[string]int64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(b, "%s{%s=%q} %d\n", name, label, k, vals[k])
	}
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
		// Level by status so operators can filter: 5xx → error, 4xx → warn.
		lvl := slog.LevelInfo
		switch {
		case rec.status >= 500:
			lvl = slog.LevelError
		case rec.status >= 400:
			lvl = slog.LevelWarn
		}
		slog.Default().Log(r.Context(), lvl, "http_request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"ip", clientIP(r),
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
		if s.cookieSecure() {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	b.WriteString(s.metrics.render())

	b.WriteString("# HELP omni_identity_build_info Build version (always 1).\n")
	b.WriteString("# TYPE omni_identity_build_info gauge\n")
	fmt.Fprintf(&b, "omni_identity_build_info{version=%q} 1\n", BuildVersion)

	if n, err := s.db.CountActiveSessions(r.Context()); err == nil {
		b.WriteString("# HELP omni_identity_active_sessions Current non-expired browser sessions.\n")
		b.WriteString("# TYPE omni_identity_active_sessions gauge\n")
		fmt.Fprintf(&b, "omni_identity_active_sessions %d\n", n)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
