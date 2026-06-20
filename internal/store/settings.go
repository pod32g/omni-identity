package store

import (
	"context"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

const settingsColumns = `issuer, public_url, token_ttl, refresh_token_ttl, max_failed_logins, ` +
	`lockout_duration, password_min_length, require_upper, require_lower, require_number, ` +
	`require_symbol, session_idle_timeout, session_lifetime, cookie_secure, seeded, updated_at`

// GetSettings returns the single settings row (id = 1), seeded by migration.
func (d *DB) GetSettings(ctx context.Context) (*model.Settings, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT `+settingsColumns+` FROM settings WHERE id = 1`)
	var s model.Settings
	err := row.Scan(&s.Issuer, &s.PublicURL, &s.TokenTTL, &s.RefreshTokenTTL,
		&s.MaxFailedLogins, &s.LockoutDuration, &s.PasswordMinLength,
		&s.RequireUpper, &s.RequireLower, &s.RequireNumber, &s.RequireSymbol,
		&s.SessionIdleTimeout, &s.SessionLifetime, &s.CookieSecure, &s.Seeded,
		&s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// UpdateSettings writes the editable settings and marks the row seeded.
func (d *DB) UpdateSettings(ctx context.Context, s *model.Settings) error {
	_, err := d.sql.ExecContext(ctx, `
		UPDATE settings SET issuer = ?, public_url = ?, token_ttl = ?,
			refresh_token_ttl = ?, max_failed_logins = ?, lockout_duration = ?,
			password_min_length = ?, require_upper = ?, require_lower = ?,
			require_number = ?, require_symbol = ?, session_idle_timeout = ?,
			session_lifetime = ?, cookie_secure = ?, seeded = TRUE, updated_at = ?
		WHERE id = 1`,
		s.Issuer, s.PublicURL, s.TokenTTL, s.RefreshTokenTTL, s.MaxFailedLogins,
		s.LockoutDuration, s.PasswordMinLength, s.RequireUpper, s.RequireLower,
		s.RequireNumber, s.RequireSymbol, s.SessionIdleTimeout,
		s.SessionLifetime, s.CookieSecure, time.Now().UTC())
	return err
}
