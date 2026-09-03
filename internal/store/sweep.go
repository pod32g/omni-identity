package store

import (
	"context"
	"time"
)

// SweepExpired deletes rows whose usefulness ended before now: expired
// sessions, authorization codes and parked requests, pending MFA challenges,
// one-time password tokens, RFC 8628 device codes, WebAuthn ceremonies, and
// replay-guard identifiers. Everything here is either already unusable or
// re-derivable; nothing with audit value is touched. Returns counts by table.
func (d *DB) SweepExpired(ctx context.Context, now time.Time) (map[string]int64, error) {
	now = now.UTC()
	counts := map[string]int64{}
	run := func(name string, f func() (int64, error)) error {
		n, err := f()
		if err != nil {
			return err
		}
		counts[name] = n
		return nil
	}
	steps := []struct {
		name string
		f    func() (int64, error)
	}{
		{"sessions", func() (int64, error) { return d.DeleteExpiredSessions(ctx, now) }},
		{"authorization_codes", func() (int64, error) { return d.DeleteExpiredAuthCodes(ctx, now) }},
		{"auth_requests", func() (int64, error) { return d.DeleteExpiredAuthRequests(ctx) }},
		{"login_challenges", func() (int64, error) { return d.deleteExpiredRows(ctx, "login_challenges", now) }},
		{"password_tokens", func() (int64, error) { return d.deleteExpiredRows(ctx, "password_tokens", now) }},
		{"device_codes", func() (int64, error) { return d.DeleteExpiredDeviceCodes(ctx, now) }},
		{"webauthn_ceremonies", func() (int64, error) { return d.DeleteExpiredWebAuthnCeremonies(ctx, now) }},
		{"device_assertion_jtis", func() (int64, error) { return d.deleteExpiredRows(ctx, "device_assertion_jtis", now) }},
	}
	for _, s := range steps {
		if err := run(s.name, s.f); err != nil {
			return counts, err
		}
	}
	return counts, nil
}

// deleteExpiredRows removes rows of a fixed, code-supplied table whose
// expires_at is in the past.
func (d *DB) deleteExpiredRows(ctx context.Context, table string, now time.Time) (int64, error) {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM `+table+` WHERE expires_at < ?`, now.UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
