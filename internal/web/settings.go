package web

import (
	"context"
	"sync"
	"time"

	"github.com/pod32g/omni-identity/internal/config"
	"github.com/pod32g/omni-identity/internal/model"
)

// SettingsView is the parsed, live view of the admin-editable settings. It is
// the single source of truth read by the token issuer, session manager, and
// request handlers at use-time.
type SettingsView struct {
	Issuer             string
	PublicURL          string
	TokenTTL           time.Duration
	RefreshTokenTTL    time.Duration
	MaxFailedLogins    int
	LockoutDuration    time.Duration
	PasswordMinLength  int
	SessionIdleTimeout time.Duration
	SessionLifetime    time.Duration
	CookieSecure       bool
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
	db  settingsStore
	mu  sync.RWMutex
	v   SettingsView
	def SettingsView // config-derived defaults (for "reset to defaults")
}

// newSettingsService builds the service, seeding the DB row from cfg on first
// run, then caching the parsed view.
func newSettingsService(db settingsStore, cfg *config.Config, defaultSessionLifetime time.Duration) *settingsService {
	s := &settingsService{db: db}
	s.def = SettingsView{
		Issuer:             cfg.Security.Issuer,
		PublicURL:          cfg.Server.PublicURL,
		TokenTTL:           cfg.Security.TokenTTL,
		RefreshTokenTTL:    cfg.Security.RefreshTokenTTL,
		MaxFailedLogins:    cfg.Security.MaxFailedLogins,
		LockoutDuration:    cfg.Security.LockoutDuration,
		PasswordMinLength:  cfg.Security.PasswordMinLength,
		SessionIdleTimeout: cfg.Security.SessionIdleTimeout,
		SessionLifetime:    defaultSessionLifetime,
		CookieSecure:       cfg.Cookies.Secure,
	}
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
		s.v = viewFromModel(row, s.def)
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
	s.v = viewFromModel(row, s.def)
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
		Issuer:             m.Issuer,
		PublicURL:          m.PublicURL,
		TokenTTL:           parseDurOr(m.TokenTTL, def.TokenTTL),
		RefreshTokenTTL:    parseDurOr(m.RefreshTokenTTL, def.RefreshTokenTTL),
		MaxFailedLogins:    m.MaxFailedLogins,
		LockoutDuration:    parseDurOr(m.LockoutDuration, def.LockoutDuration),
		PasswordMinLength:  m.PasswordMinLength,
		SessionIdleTimeout: parseDurOr(m.SessionIdleTimeout, def.SessionIdleTimeout),
		SessionLifetime:    parseDurOr(m.SessionLifetime, def.SessionLifetime),
		CookieSecure:       m.CookieSecure,
	}
}

// toModel renders a view back into a storable Settings row.
func (v SettingsView) toModel() *model.Settings {
	return &model.Settings{
		Issuer:             v.Issuer,
		PublicURL:          v.PublicURL,
		TokenTTL:           v.TokenTTL.String(),
		RefreshTokenTTL:    v.RefreshTokenTTL.String(),
		MaxFailedLogins:    v.MaxFailedLogins,
		LockoutDuration:    v.LockoutDuration.String(),
		PasswordMinLength:  v.PasswordMinLength,
		SessionIdleTimeout: v.SessionIdleTimeout.String(),
		SessionLifetime:    v.SessionLifetime.String(),
		CookieSecure:       v.CookieSecure,
	}
}

func parseDurOr(s string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return def
}
