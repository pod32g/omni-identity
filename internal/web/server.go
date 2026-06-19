// Package web wires the HTTP router, middleware, and handlers together into a
// single Server value that satisfies http.Handler.
package web

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/config"
	"github.com/pod32g/omni-identity/internal/store"
)

// sessionTTL is the browser login session lifetime.
const sessionTTL = 12 * time.Hour

// Server holds shared dependencies and the route mux.
type Server struct {
	cfg      *config.Config
	db       *store.DB
	sessions *auth.SessionManager
	tmpl     *templates
	mux      *http.ServeMux
}

// NewServer builds a Server with all routes registered.
func NewServer(cfg *config.Config, db *store.DB) (*Server, error) {
	tmpl, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		db:       db,
		sessions: auth.NewSessionManager(db, cfg.Cookies.Secure, sessionTTL),
		tmpl:     tmpl,
		mux:      http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)

	s.mux.HandleFunc("GET /login", s.handleLoginForm)
	s.mux.HandleFunc("POST /login", s.handleLoginSubmit)
	s.mux.HandleFunc("POST /logout", s.handleLogout)
	s.mux.HandleFunc("GET /setup", s.handleSetupForm)
	s.mux.HandleFunc("POST /setup", s.handleSetupSubmit)

	s.mux.HandleFunc("GET /{$}", s.handleRoot)
}

// ServeHTTP dispatches to the route mux.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status, code := "ok", http.StatusOK
	if s.db != nil {
		if err := s.db.Ping(); err != nil {
			status, code = "degraded", http.StatusServiceUnavailable
		}
	}
	writeJSON(w, code, map[string]string{"status": status})
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if _, err := s.sessions.Current(r); err == nil {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
