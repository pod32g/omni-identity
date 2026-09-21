package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/config"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/store"
)

// This file backs the `admin ensure` and `client ensure` commands: idempotent
// provisioning for installers that would otherwise have to drive the setup
// wizard and the admin forms over HTTP. It lives in this package so the rules
// are the ones the UI applies — the same password policy, the same redirect
// URI policy read from the live settings — and not a second copy of them.
//
// Running these requires what `serve` requires: the configuration and the
// database. They are not a network API and add no new way in.

// Outcomes of an ensure call.
const (
	EnsureCreated   = "created"
	EnsureUpdated   = "updated"
	EnsureUnchanged = "unchanged"
)

// ensureActor marks audit events written by the commands rather than a session.
const ensureActor = "omni-identity-cli"

// minClientSecretLen is the shortest caller-supplied client secret accepted.
// Client secrets are stored as an unsalted SHA-256 (see auth.HashToken), which
// is only sound for high-entropy values; generated ones are 32 characters.
const minClientSecretLen = 32

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// EnsureStore is the persistence the ensure commands need (*store.DB).
type EnsureStore interface {
	settingsStore
	GetUserByUsername(ctx context.Context, username string) (*model.User, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	CreateUser(ctx context.Context, u *model.User) error
	GetClient(ctx context.Context, clientID string) (*model.Client, error)
	CreateClient(ctx context.Context, c *model.Client) error
	UpdateClient(ctx context.Context, c *model.Client) error
	SetClientSecretHash(ctx context.Context, clientID, hash string) error
	AppendAuditEvent(ctx context.Context, e *model.AuditEvent) error
}

// ensureSettings returns the settings in force: the stored row once it has been
// seeded, the config-derived defaults before that. Unlike the server it never
// seeds the row, so running a command does not change what `serve` will do.
func ensureSettings(ctx context.Context, db EnsureStore, cfg *config.Config) SettingsView {
	def := settingsDefaults(cfg)
	row, err := db.GetSettings(ctx)
	if err != nil || row == nil || !row.Seeded {
		return def
	}
	return sanitizeSettingsView(viewFromModel(row, def), def, cfg.Server.AllowInsecureHTTP)
}

func ensureAudit(ctx context.Context, db EnsureStore, event string, e auditEntry) {
	ev := &model.AuditEvent{
		ID:        uuid.NewString(),
		CreatedAt: time.Now().UTC(),
		Event:     event,
		Username:  e.username,
		ClientID:  e.clientID,
		UserAgent: ensureActor,
		Success:   e.success,
		Detail:    e.detail,
	}
	logAuditEvent(ev)
	if err := db.AppendAuditEvent(ctx, ev); err != nil {
		slog.Error("audit append failed", "event", event, "error", err.Error())
	}
}

// AdminSpec describes the administrator `admin ensure` should guarantee.
type AdminSpec struct {
	Username string
	Email    string
	// Password is used only when the account is created.
	Password string
}

// AdminResult reports what `admin ensure` did.
type AdminResult struct {
	Result   string `json:"result"`
	UserID   string `json:"user_id"`
	Username string `json:"username"`
}

// EnsureAdmin creates the local administrator if it does not exist.
//
// It never changes an existing account: not its password, not its role. A
// username that exists without administrator rights, disabled, or owned by an
// external directory is an error, because silently promoting or re-enabling an
// account is not something an installer should be able to do by accident.
func EnsureAdmin(ctx context.Context, db EnsureStore, cfg *config.Config, spec AdminSpec) (*AdminResult, error) {
	username, email := strings.TrimSpace(spec.Username), strings.TrimSpace(spec.Email)
	if username == "" || email == "" {
		return nil, errors.New("username and email are required")
	}

	existing, err := db.GetUserByUsername(ctx, username)
	switch {
	case err == nil:
		switch {
		case existing.AuthSource != "" && existing.AuthSource != "local":
			return nil, fmt.Errorf("user %q is managed by %q, not a local account", username, existing.AuthSource)
		case !existing.IsAdmin:
			return nil, fmt.Errorf("user %q exists but is not an administrator; promote it from the admin UI", username)
		case existing.Disabled:
			return nil, fmt.Errorf("administrator %q exists but is disabled; enable it from the admin UI", username)
		}
		return &AdminResult{Result: EnsureUnchanged, UserID: existing.ID, Username: existing.Username}, nil
	case !errors.Is(err, store.ErrNotFound):
		return nil, fmt.Errorf("look up user: %w", err)
	}

	if other, err := db.GetUserByEmail(ctx, email); err == nil {
		return nil, fmt.Errorf("email %q already belongs to user %q", email, other.Username)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("look up email: %w", err)
	}
	if spec.Password == "" {
		return nil, errors.New("a password is required to create the administrator")
	}
	if msg := auth.ValidatePassword(spec.Password, username, email, ensureSettings(ctx, db, cfg).PasswordPolicy()); msg != "" {
		return nil, errors.New(msg)
	}
	hash, err := auth.HashPassword(spec.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	now := time.Now().UTC()
	user := &model.User{
		ID:           uuid.NewString(),
		Username:     username,
		Email:        email,
		PasswordHash: hash,
		IsAdmin:      true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := db.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("create administrator: %w", err)
	}
	ensureAudit(ctx, db, evtUserCreated, auditEntry{username: username, success: true, detail: "admin ensure"})
	return &AdminResult{Result: EnsureCreated, UserID: user.ID, Username: username}, nil
}

// ClientSpec describes the client `client ensure` should guarantee. A nil
// field is "not specified": it takes its default on a new client and is left
// as it is on an existing one, so settings made in the admin UI survive.
type ClientSpec struct {
	ClientID               string
	Name                   *string
	Type                   *string
	RedirectURIs           []string // nil = not specified
	PostLogoutRedirectURIs []string // nil = not specified
	Scopes                 []string // nil = not specified
	DisplayName            *string
	LogoURL                *string
	HomepageURL            *string
	SkipConsent            *bool
	// Secret, when set, becomes the client's secret (confidential clients).
	// When empty a new confidential client gets a generated one, returned once.
	Secret string
}

// ClientResult reports what `client ensure` did.
type ClientResult struct {
	Result   string   `json:"result"`
	ClientID string   `json:"client_id"`
	Type     string   `json:"type"`
	Changed  []string `json:"changed,omitempty"`
	Disabled bool     `json:"disabled,omitempty"`
	// ClientSecret is set only when this call generated the secret.
	ClientSecret string `json:"client_secret,omitempty"`
}

// defaultEnsureScopes is what a new client gets when no scopes are specified.
var defaultEnsureScopes = []string{"openid", "profile", "email"}

// EnsureClient creates the client or brings the specified fields in line.
//
// It does not enable a disabled client and does not change a client's type;
// both are deliberate decisions for the admin UI.
func EnsureClient(ctx context.Context, db EnsureStore, cfg *config.Config, spec ClientSpec) (*ClientResult, error) {
	if !clientIDPattern.MatchString(spec.ClientID) {
		return nil, errors.New("client id must be 1-64 characters of A-Z a-z 0-9 . _ - and start with a letter or digit")
	}
	if spec.Secret != "" && len(spec.Secret) < minClientSecretLen {
		return nil, fmt.Errorf("client secret must be at least %d characters of random data", minClientSecretLen)
	}
	cur := ensureSettings(ctx, db, cfg)

	existing, err := db.GetClient(ctx, spec.ClientID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("look up client: %w", err)
	}
	if err != nil {
		return createEnsuredClient(ctx, db, cur, spec)
	}

	if spec.Type != nil && *spec.Type != existing.Type {
		return nil, fmt.Errorf("client %q is %s; its type can only be changed from the admin UI", existing.ClientID, existing.Type)
	}
	if spec.Secret != "" && existing.Type != model.ClientTypeConfidential {
		return nil, fmt.Errorf("client %q is public and has no secret", existing.ClientID)
	}

	var changed []string
	setString := func(field string, dst *string, src *string) {
		if src != nil && strings.TrimSpace(*src) != *dst {
			*dst = strings.TrimSpace(*src)
			changed = append(changed, field)
		}
	}
	setList := func(field string, dst *[]string, src []string) {
		if src != nil && !slices.Equal(*dst, src) {
			*dst = src
			changed = append(changed, field)
		}
	}
	setString("name", &existing.Name, spec.Name)
	setList("redirect_uris", &existing.RedirectURIs, spec.RedirectURIs)
	setList("post_logout_redirect_uris", &existing.PostLogoutRedirectURIs, spec.PostLogoutRedirectURIs)
	setList("scopes", &existing.AllowedScopes, spec.Scopes)
	setString("display_name", &existing.DisplayName, spec.DisplayName)
	setString("logo_url", &existing.LogoURL, spec.LogoURL)
	setString("homepage_url", &existing.HomepageURL, spec.HomepageURL)
	if spec.SkipConsent != nil && *spec.SkipConsent != existing.SkipConsent {
		existing.SkipConsent = *spec.SkipConsent
		changed = append(changed, "skip_consent")
	}

	if len(changed) > 0 {
		if msg := formFromClient(existing).validate(cur.AllowLoopbackHTTPRedirect, cur.AllowPrivateNetworkHTTPRedirect, cur.AllowPrivateSchemeRedirect); msg != "" {
			return nil, errors.New(msg)
		}
		if err := db.UpdateClient(ctx, existing); err != nil {
			return nil, fmt.Errorf("update client: %w", err)
		}
		ensureAudit(ctx, db, evtClientUpdated, auditEntry{clientID: existing.ClientID, success: true,
			detail: "client ensure: " + strings.Join(changed, ", ")})
	}
	if spec.Secret != "" && !auth.SecretMatches(spec.Secret, existing.ClientSecretHash) {
		if err := db.SetClientSecretHash(ctx, existing.ClientID, auth.HashToken(spec.Secret)); err != nil {
			return nil, fmt.Errorf("set client secret: %w", err)
		}
		changed = append(changed, "secret")
		ensureAudit(ctx, db, evtClientSecret, auditEntry{clientID: existing.ClientID, success: true, detail: "client ensure"})
	}

	res := &ClientResult{Result: EnsureUnchanged, ClientID: existing.ClientID, Type: existing.Type, Changed: changed, Disabled: existing.Disabled}
	if len(changed) > 0 {
		res.Result = EnsureUpdated
	}
	return res, nil
}

func createEnsuredClient(ctx context.Context, db EnsureStore, cur SettingsView, spec ClientSpec) (*ClientResult, error) {
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return strings.TrimSpace(*p)
	}
	now := time.Now().UTC()
	c := &model.Client{
		ClientID:               spec.ClientID,
		Name:                   deref(spec.Name),
		Type:                   model.ClientTypeConfidential,
		RedirectURIs:           spec.RedirectURIs,
		AllowedScopes:          spec.Scopes,
		DisplayName:            deref(spec.DisplayName),
		LogoURL:                deref(spec.LogoURL),
		HomepageURL:            deref(spec.HomepageURL),
		PostLogoutRedirectURIs: spec.PostLogoutRedirectURIs,
		SkipConsent:            spec.SkipConsent != nil && *spec.SkipConsent,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if spec.Type != nil {
		c.Type = *spec.Type
	}
	if c.AllowedScopes == nil {
		c.AllowedScopes = slices.Clone(defaultEnsureScopes)
	}
	if msg := formFromClient(c).validate(cur.AllowLoopbackHTTPRedirect, cur.AllowPrivateNetworkHTTPRedirect, cur.AllowPrivateSchemeRedirect); msg != "" {
		return nil, errors.New(msg)
	}

	res := &ClientResult{Result: EnsureCreated, ClientID: c.ClientID, Type: c.Type}
	switch {
	case c.Type != model.ClientTypeConfidential:
		if spec.Secret != "" {
			return nil, errors.New("a public client has no secret")
		}
	case spec.Secret != "":
		c.ClientSecretHash = auth.HashToken(spec.Secret)
	default:
		res.ClientSecret = auth.RandomToken(24)
		c.ClientSecretHash = auth.HashToken(res.ClientSecret)
	}
	if err := db.CreateClient(ctx, c); err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}
	ensureAudit(ctx, db, evtClientCreated, auditEntry{clientID: c.ClientID, success: true, detail: "client ensure"})
	return res, nil
}

func formFromClient(c *model.Client) clientForm {
	return clientForm{
		clientID:       c.ClientID,
		name:           c.Name,
		clientType:     c.Type,
		redirectURIs:   c.RedirectURIs,
		scopes:         c.AllowedScopes,
		displayName:    c.DisplayName,
		logoURL:        c.LogoURL,
		homepageURL:    c.HomepageURL,
		postLogoutURIs: c.PostLogoutRedirectURIs,
		skipConsent:    c.SkipConsent,
	}
}
