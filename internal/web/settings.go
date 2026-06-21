package web

import (
	"context"
	"sync"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/config"
	"github.com/pod32g/omni-identity/internal/model"
)

// SettingsView is the parsed, live view of the admin-editable settings. It is
// the single source of truth read by the token issuer, session manager, and
// request handlers at use-time.
type SettingsView struct {
	Issuer                    string
	PublicURL                 string
	TokenTTL                  time.Duration
	RefreshTokenTTL           time.Duration
	MaxFailedLogins           int
	LockoutDuration           time.Duration
	RateLimitWindow           time.Duration
	LoginIPMaxAttempts        int
	PasswordVerifyConcurrency int
	MaxLoginUsernameBytes     int
	MaxLoginPasswordBytes     int
	AllowLoopbackHTTPRedirect bool
	PasswordMinLength         int
	RequireUpper              bool
	RequireLower              bool
	RequireNumber             bool
	RequireSymbol             bool
	SessionIdleTimeout        time.Duration
	SessionLifetime           time.Duration
	CookieSecure              bool
	MaxLogoBytes              int
}

// PasswordPolicy renders the live complexity policy.
func (v SettingsView) PasswordPolicy() auth.PasswordPolicy {
	return auth.PasswordPolicy{
		MinLength:     v.PasswordMinLength,
		RequireUpper:  v.RequireUpper,
		RequireLower:  v.RequireLower,
		RequireNumber: v.RequireNumber,
		RequireSymbol: v.RequireSymbol,
	}
}

// settingsStore is the persistence surface the service needs.
type settingsStore interface {
	GetSettings(ctx context.Context) (*model.Settings, error)
	UpdateSettings(ctx context.Context, s *model.Settings) error
}

// settingsService loads and caches the settings row, seeding it from config on
// first run, and exposes a live view plus the provider interfaces consumed by
// the token issuer and session manager.
type settingsService struct {
	db                settingsStore
	mu                sync.RWMutex
	v                 SettingsView
	def               SettingsView // config-derived defaults (for "reset to defaults")
	allowInsecureHTTP bool
}

// newSettingsService builds the service, seeding the DB row from cfg on first
// run, then caching the parsed view.
func newSettingsService(db settingsStore, cfg *config.Config, defaultSessionLifetime time.Duration) *settingsService {
	s := &settingsService{db: db, allowInsecureHTTP: cfg.Server.AllowInsecureHTTP}
	s.def = SettingsView{
		Issuer:                    cfg.Security.Issuer,
		PublicURL:                 cfg.Server.PublicURL,
		TokenTTL:                  cfg.Security.TokenTTL,
		RefreshTokenTTL:           cfg.Security.RefreshTokenTTL,
		MaxFailedLogins:           cfg.Security.MaxFailedLogins,
		LockoutDuration:           cfg.Security.LockoutDuration,
		RateLimitWindow:           cfg.Security.RateLimitWindow,
		LoginIPMaxAttempts:        cfg.Security.LoginIPMaxAttempts,
		PasswordVerifyConcurrency: cfg.Security.PasswordVerifyConcurrency,
		MaxLoginUsernameBytes:     cfg.Security.MaxLoginUsernameBytes,
		MaxLoginPasswordBytes:     cfg.Security.MaxLoginPasswordBytes,
		AllowLoopbackHTTPRedirect: cfg.Security.AllowLoopbackHTTPRedirect,
		PasswordMinLength:         cfg.Security.PasswordMinLength,
		RequireUpper:              cfg.Security.RequireUpper,
		RequireLower:              cfg.Security.RequireLower,
		RequireNumber:             cfg.Security.RequireNumber,
		RequireSymbol:             cfg.Security.RequireSymbol,
		SessionIdleTimeout:        cfg.Security.SessionIdleTimeout,
		SessionLifetime:           cfg.Security.SessionLifetime,
		CookieSecure:              cfg.Cookies.Secure,
		MaxLogoBytes:              cfg.Uploads.MaxLogoBytes,
	}
	s.def = withRuntimeSettingDefaults(s.def)
	s.v = s.def

	ctx := context.Background()
	row, err := db.GetSettings(ctx)
	if err != nil {
		return s // fall back to config defaults
	}
	if !row.Seeded {
		_ = db.UpdateSettings(ctx, s.def.toModel())
		row, _ = db.GetSettings(ctx)
	}
	if row != nil {
		s.mu.Lock()
		s.v = sanitizeSettingsView(viewFromModel(row, s.def), s.def, s.allowInsecureHTTP)
		s.mu.Unlock()
	}
	return s
}

// Current returns the cached live settings view.
func (s *settingsService) Current() SettingsView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v
}

// Defaults returns the config-derived defaults (for "reset to config").
func (s *settingsService) Defaults() SettingsView { return s.def }

// Reload refreshes the cache from the store.
func (s *settingsService) Reload(ctx context.Context) {
	row, err := s.db.GetSettings(ctx)
	if err != nil || row == nil {
		return
	}
	s.mu.Lock()
	s.v = sanitizeSettingsView(viewFromModel(row, s.def), s.def, s.allowInsecureHTTP)
	s.mu.Unlock()
}

// --- tokens.IssuerConfig ---

func (s *settingsService) Issuer() string           { return s.Current().Issuer }
func (s *settingsService) AccessTTL() time.Duration { return s.Current().TokenTTL }
func (s *settingsService) IDTTL() time.Duration     { return s.Current().TokenTTL }

// --- auth.SessionConfig ---

func (s *settingsService) Secure() bool               { return s.Current().CookieSecure }
func (s *settingsService) Lifetime() time.Duration    { return s.Current().SessionLifetime }
func (s *settingsService) IdleTimeout() time.Duration { return s.Current().SessionIdleTimeout }

// viewFromModel parses a stored Settings row into a view, falling back to def
// for any unparseable duration.
func viewFromModel(m *model.Settings, def SettingsView) SettingsView {
	return SettingsView{
		Issuer:                    m.Issuer,
		PublicURL:                 m.PublicURL,
		TokenTTL:                  parseDurOr(m.TokenTTL, def.TokenTTL),
		RefreshTokenTTL:           parseDurOr(m.RefreshTokenTTL, def.RefreshTokenTTL),
		MaxFailedLogins:           m.MaxFailedLogins,
		LockoutDuration:           parseDurOr(m.LockoutDuration, def.LockoutDuration),
		RateLimitWindow:           parseDurOr(m.RateLimitWindow, def.RateLimitWindow),
		LoginIPMaxAttempts:        m.LoginIPMaxAttempts,
		PasswordVerifyConcurrency: m.PasswordVerifyConcurrency,
		MaxLoginUsernameBytes:     m.MaxLoginUsernameBytes,
		MaxLoginPasswordBytes:     m.MaxLoginPasswordBytes,
		AllowLoopbackHTTPRedirect: m.AllowLoopbackHTTPRedirect,
		PasswordMinLength:         m.PasswordMinLength,
		RequireUpper:              m.RequireUpper,
		RequireLower:              m.RequireLower,
		RequireNumber:             m.RequireNumber,
		RequireSymbol:             m.RequireSymbol,
		SessionIdleTimeout:        parseDurOr(m.SessionIdleTimeout, def.SessionIdleTimeout),
		SessionLifetime:           parseDurOr(m.SessionLifetime, def.SessionLifetime),
		CookieSecure:              m.CookieSecure,
		MaxLogoBytes:              m.MaxLogoBytes,
	}
}

func sanitizeSettingsView(v, def SettingsView, allowInsecureHTTP bool) SettingsView {
	v = withRuntimeSettingDefaults(v)
	issuer, _, err := config.NormalizePublicURL("issuer", v.Issuer, allowInsecureHTTP)
	if err != nil {
		return def
	}
	publicURL, parsedPublicURL, err := config.NormalizePublicURL("public URL", v.PublicURL, allowInsecureHTTP)
	if err != nil {
		return def
	}
	v.Issuer = issuer
	v.PublicURL = publicURL
	if parsedPublicURL.Scheme == "https" {
		v.CookieSecure = true
	}
	if parsedPublicURL.Scheme == "http" {
		v.CookieSecure = false
	}
	return v
}

// toModel renders a view back into a storable Settings row.
func (v SettingsView) toModel() *model.Settings {
	return &model.Settings{
		Issuer:                    v.Issuer,
		PublicURL:                 v.PublicURL,
		TokenTTL:                  v.TokenTTL.String(),
		RefreshTokenTTL:           v.RefreshTokenTTL.String(),
		MaxFailedLogins:           v.MaxFailedLogins,
		LockoutDuration:           v.LockoutDuration.String(),
		RateLimitWindow:           v.RateLimitWindow.String(),
		LoginIPMaxAttempts:        v.LoginIPMaxAttempts,
		PasswordVerifyConcurrency: v.PasswordVerifyConcurrency,
		MaxLoginUsernameBytes:     v.MaxLoginUsernameBytes,
		MaxLoginPasswordBytes:     v.MaxLoginPasswordBytes,
		AllowLoopbackHTTPRedirect: v.AllowLoopbackHTTPRedirect,
		PasswordMinLength:         v.PasswordMinLength,
		RequireUpper:              v.RequireUpper,
		RequireLower:              v.RequireLower,
		RequireNumber:             v.RequireNumber,
		RequireSymbol:             v.RequireSymbol,
		SessionIdleTimeout:        v.SessionIdleTimeout.String(),
		SessionLifetime:           v.SessionLifetime.String(),
		CookieSecure:              v.CookieSecure,
		MaxLogoBytes:              v.MaxLogoBytes,
	}
}

func withRuntimeSettingDefaults(v SettingsView) SettingsView {
	if v.TokenTTL <= 0 {
		v.TokenTTL = 15 * time.Minute
	}
	if v.RefreshTokenTTL <= 0 {
		v.RefreshTokenTTL = 720 * time.Hour
	}
	if v.MaxFailedLogins < 1 {
		v.MaxFailedLogins = defaultLoginMaxAttempts
	}
	if v.LockoutDuration <= 0 {
		v.LockoutDuration = defaultRateLimitWindow
	}
	if v.RateLimitWindow <= 0 {
		v.RateLimitWindow = defaultRateLimitWindow
	}
	if v.LoginIPMaxAttempts < 1 {
		v.LoginIPMaxAttempts = defaultLoginIPMaxAttempts
	}
	if v.PasswordVerifyConcurrency < 1 {
		v.PasswordVerifyConcurrency = defaultPasswordVerifyConcurrency
	}
	if v.MaxLoginUsernameBytes < 1 {
		v.MaxLoginUsernameBytes = defaultMaxLoginUsernameBytes
	}
	if v.MaxLoginPasswordBytes < 1 {
		v.MaxLoginPasswordBytes = defaultMaxLoginPasswordBytes
	}
	if v.PasswordMinLength < 1 {
		v.PasswordMinLength = 12
	}
	if v.SessionLifetime <= 0 {
		v.SessionLifetime = sessionTTL
	}
	if v.MaxLogoBytes < 1 {
		v.MaxLogoBytes = defaultMaxLogoBytes
	}
	return v
}

func parseDurOr(s string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return def
}
