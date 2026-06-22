// Package web wires the HTTP router, middleware, and handlers together into a
// single Server value that satisfies http.Handler.
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/authn"
	"github.com/pod32g/omni-identity/internal/config"
	"github.com/pod32g/omni-identity/internal/crypto"
	"github.com/pod32g/omni-identity/internal/email"
	"github.com/pod32g/omni-identity/internal/ldap"
	"github.com/pod32g/omni-identity/internal/store"
	"github.com/pod32g/omni-identity/internal/tokens"
)

// sessionTTL is the browser login session lifetime.
const sessionTTL = 12 * time.Hour

// Server holds shared dependencies and the route mux.
type Server struct {
	cfg          *config.Config
	db           *store.DB
	sessions     *auth.SessionManager
	keys         *tokens.KeyManager
	issuer       *tokens.Issuer
	tmpl         *templates
	branding     *brandingService
	settings     *settingsService
	loginRate    *rateLimiter
	loginIPRate  *rateLimiter
	mfaRate      *rateLimiter
	forgotRate   *rateLimiter
	verifyMu     sync.Mutex
	verifyActive int
	mailer       email.Sender
	enc          *crypto.Encryptor
	connectors   []authn.PasswordConnector // external auth sources (e.g. LDAP); empty by default
	directory    authn.DirectoryManager    // write-capable directory client; nil unless LDAP+bind configured. Exposure gated live by the ldap_manage_enabled setting
	metrics      *metrics
	mux          *http.ServeMux
	handler      http.Handler
}

// NewServer builds a Server with all routes registered. It ensures signing keys
// exist (generating them on first run).
func NewServer(cfg *config.Config, db *store.DB) (*Server, error) {
	tmpl, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	km, err := tokens.NewKeyManager(context.Background(), db)
	if err != nil {
		return nil, err
	}

	// Persisted server secret used to encrypt sensitive columns (TOTP secrets).
	keyB64, err := db.GetOrCreateAppSecret(context.Background(), crypto.GenerateKeyB64)
	if err != nil {
		return nil, err
	}
	enc, err := crypto.NewEncryptorFromB64(keyB64)
	if err != nil {
		return nil, err
	}

	// External authentication connectors (off unless configured). LDAP is the
	// first; the login flow consults them after the local password store.
	var connectors []authn.PasswordConnector
	var directory authn.DirectoryManager
	if cfg.LDAP.Enabled {
		client, err := ldap.New(ldap.Config{
			URL: cfg.LDAP.URL, StartTLS: cfg.LDAP.StartTLS,
			BindDN: cfg.LDAP.BindDN, BindPassword: cfg.LDAP.BindPassword,
			BaseDN: cfg.LDAP.BaseDN, UserFilter: cfg.LDAP.UserFilter,
			AttrUsername: cfg.LDAP.AttrUsername, AttrEmail: cfg.LDAP.AttrEmail,
			AttrDisplayName: cfg.LDAP.AttrDisplayName,
			AdminGroupDN:    cfg.LDAP.AdminGroupDN, GroupFilter: cfg.LDAP.GroupFilter,
			CACertFile: cfg.LDAP.CACertFile, InsecureSkipVerify: cfg.LDAP.InsecureSkipVerify,
			Timeout:      cfg.LDAP.Timeout,
			PeopleBaseDN: cfg.LDAP.PeopleBaseDN, RDNAttr: cfg.LDAP.RDNAttr,
			UserObjectClasses: cfg.LDAP.UserObjectClasses,
		})
		if err != nil {
			return nil, fmt.Errorf("init ldap connector: %w", err)
		}
		connectors = append(connectors, client)
		// The client is write-capable whenever a privileged bind is configured.
		// Whether management is actually *exposed* is gated live by the
		// ldap_manage_enabled setting (see directoryManager); the directory stays
		// the source of truth and the local row remains a thin mirror.
		if cfg.LDAP.BindDN != "" {
			directory = client
		}
	}

	sessions := auth.NewSessionManager(db, cfg.Cookies.Secure, sessionTTL)
	sessions.SetIdleTimeout(cfg.Security.SessionIdleTimeout)
	issuer := tokens.NewIssuer(km, cfg.Security.Issuer, cfg.Security.TokenTTL, cfg.Security.TokenTTL)

	// Live, admin-editable settings; seeded from config on first run.
	settings := newSettingsService(db, cfg, sessionTTL)
	// Issuer and session manager read issuer/TTLs/cookie-Secure live.
	issuer.SetConfigProvider(settings)
	sessions.SetConfigProvider(settings)

	s := &Server{
		cfg:         cfg,
		db:          db,
		sessions:    sessions,
		keys:        km,
		issuer:      issuer,
		tmpl:        tmpl,
		branding:    newBrandingService(db.GetBranding),
		settings:    settings,
		loginRate:   newRateLimiter(),
		loginIPRate: newRateLimiter(),
		mfaRate:     newRateLimiter(),
		forgotRate:  newRateLimiter(),
		mailer: &email.SMTPSender{
			Host: cfg.SMTP.Host, Port: cfg.SMTP.Port, Username: cfg.SMTP.Username,
			Password: cfg.SMTP.Password, From: cfg.SMTP.From, StartTLS: cfg.SMTP.StartTLS,
		},
		enc:        enc,
		connectors: connectors,
		directory:  directory,
		metrics:    newMetrics(),
		mux:        http.NewServeMux(),
	}
	// Render branding on every page; read live so admin edits take effect.
	tmpl.brand = s.branding.Current
	s.routes()
	s.handler = s.withMiddleware(s.mux)
	return s, nil
}

// cookieSecure reports the live cookie Secure flag from editable settings.
func (s *Server) cookieSecure() bool { return s.settings.Current().CookieSecure }

// passwordPolicy is the live password-complexity policy from editable settings.
func (s *Server) passwordPolicy() auth.PasswordPolicy { return s.settings.Current().PasswordPolicy() }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /metrics", s.handleMetrics)

	s.mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	s.mux.HandleFunc("GET /jwks.json", s.handleJWKS)

	s.mux.HandleFunc("GET /oauth2/authorize", s.handleAuthorize)
	s.mux.HandleFunc("POST /oauth2/token", s.handleToken)
	s.mux.HandleFunc("POST /oauth2/revoke", s.handleRevoke)
	s.mux.HandleFunc("POST /oauth2/introspect", s.handleIntrospect)
	s.mux.HandleFunc("GET /userinfo", s.handleUserinfo)
	s.mux.HandleFunc("POST /userinfo", s.handleUserinfo)

	s.mux.HandleFunc("GET /login", s.handleLoginForm)
	s.mux.HandleFunc("POST /login", s.handleLoginSubmit)
	s.mux.HandleFunc("GET /login/mfa", s.handleMFAForm)
	s.mux.HandleFunc("POST /login/mfa", s.handleMFASubmit)
	s.mux.HandleFunc("GET /consent", s.handleConsentForm)
	s.mux.HandleFunc("POST /consent", s.handleConsentSubmit)
	s.mux.HandleFunc("GET /logout", s.handleLogoutPage)
	s.mux.HandleFunc("POST /logout", s.handleLogout)
	s.mux.HandleFunc("GET /setup", s.handleSetupForm)
	s.mux.HandleFunc("POST /setup", s.handleSetupSubmit)
	s.mux.HandleFunc("GET /set-password", s.handleSetPasswordForm)
	s.mux.HandleFunc("POST /set-password", s.handleSetPasswordSubmit)
	s.mux.HandleFunc("GET /forgot", s.handleForgotForm)
	s.mux.HandleFunc("POST /forgot", s.handleForgotSubmit)
	s.mux.HandleFunc("GET /branding/logo", s.handleBrandingLogo)

	s.mux.HandleFunc("GET /account", s.requireUser(s.handleAccount))
	s.mux.HandleFunc("POST /account/password", s.requireUser(s.handleAccountPassword))
	s.mux.HandleFunc("POST /account/sessions/revoke", s.requireUser(s.handleRevokeOtherSessions))
	s.mux.HandleFunc("GET /account/mfa/setup", s.requireUser(s.handleMFASetup))
	s.mux.HandleFunc("POST /account/mfa/enable", s.requireUser(s.handleMFAEnable))
	s.mux.HandleFunc("POST /account/mfa/disable", s.requireUser(s.handleMFADisable))

	s.mux.HandleFunc("GET /admin", s.requireAdmin(s.handleAdminHome))
	s.mux.HandleFunc("GET /admin/users", s.requireAdmin(s.handleAdminUsers))
	s.mux.HandleFunc("GET /admin/users/{id}", s.requireAdmin(s.handleAdminUserDetail))
	s.mux.HandleFunc("POST /admin/users", s.requireAdmin(s.handleAdminCreateUser))
	s.mux.HandleFunc("POST /admin/users/{id}/disable", s.requireAdmin(s.handleAdminToggleUser))
	s.mux.HandleFunc("POST /admin/users/{id}/password", s.requireAdmin(s.handleAdminUserPassword))
	s.mux.HandleFunc("POST /admin/users/{id}/profile", s.requireAdmin(s.handleAdminUpdateDirectoryUser))
	s.mux.HandleFunc("POST /admin/users/{id}/delete", s.requireAdmin(s.handleAdminDeleteUser))
	s.mux.HandleFunc("GET /admin/clients", s.requireAdmin(s.handleAdminClients))
	s.mux.HandleFunc("POST /admin/clients", s.requireAdmin(s.handleAdminCreateClient))
	s.mux.HandleFunc("GET /admin/clients/{id}", s.requireAdmin(s.handleAdminClientDetail))
	s.mux.HandleFunc("POST /admin/clients/{id}", s.requireAdmin(s.handleAdminUpdateClient))
	s.mux.HandleFunc("POST /admin/clients/{id}/disable", s.requireAdmin(s.handleAdminToggleClient))
	s.mux.HandleFunc("POST /admin/clients/{id}/rotate", s.requireAdmin(s.handleAdminRotateClient))
	s.mux.HandleFunc("POST /admin/users/{id}/unlock", s.requireAdmin(s.handleAdminUnlockUser))
	s.mux.HandleFunc("POST /admin/users/{id}/mfa/reset", s.requireAdmin(s.handleAdminResetMFA))
	s.mux.HandleFunc("POST /admin/users/{id}/reset-link", s.requireAdmin(s.handleAdminUserResetLink))
	s.mux.HandleFunc("GET /admin/settings", s.requireAdmin(s.handleAdminSettings))
	s.mux.HandleFunc("POST /admin/settings", s.requireAdmin(s.handleAdminUpdateBranding))
	s.mux.HandleFunc("POST /admin/settings/logo", s.requireAdmin(s.handleAdminUploadLogo))
	s.mux.HandleFunc("POST /admin/settings/system", s.requireAdmin(s.handleAdminUpdateSettings))
	s.mux.HandleFunc("POST /admin/settings/reset", s.requireAdmin(s.handleAdminResetSettings))
	s.mux.HandleFunc("GET /admin/audit", s.requireAdmin(s.handleAdminAudit))

	s.mux.HandleFunc("GET /{$}", s.handleRoot)
}

// ServeHTTP dispatches through the middleware chain to the route mux.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
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
