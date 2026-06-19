// Package web wires the HTTP router, middleware, and handlers together into a
// single Server value that satisfies http.Handler.
package web

import (
	"encoding/json"
	"net/http"

	"github.com/pod32g/omni-identity/internal/config"
	"github.com/pod32g/omni-identity/internal/store"
)

// Server holds shared dependencies and the route mux.
type Server struct {
	cfg *config.Config
	db  *store.DB
	mux *http.ServeMux
}

// NewServer builds a Server with all routes registered.
func NewServer(cfg *config.Config, db *store.DB) *Server {
	s := &Server{cfg: cfg, db: db, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
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

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
