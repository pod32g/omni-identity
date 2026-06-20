package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// settingBounds caps the editable durations to sane ranges.
const (
	minTokenTTL   = 1 * time.Minute
	maxTokenTTL   = 24 * time.Hour
	minRefreshTTL = 5 * time.Minute
	maxRefreshTTL = 365 * 24 * time.Hour
	maxSessionTTL = 90 * 24 * time.Hour
	minPwLen      = 8
)

// handleAdminUpdateSettings validates and persists the editable system
// settings, then refreshes the live cache so the change applies immediately.
func (s *Server) handleAdminUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}

	cur := s.settings.Current()
	next := cur // start from current, overlay form values

	form := r.PostForm
	next.Issuer = strings.TrimSpace(form.Get("issuer"))
	next.PublicURL = strings.TrimSpace(form.Get("public_url"))
	next.CookieSecure = form.Get("cookie_secure") == "on" || form.Get("cookie_secure") == "true"

	// Durations.
	var perr error
	parse := func(field string, lo, hi time.Duration, dst *time.Duration) {
		if perr != nil {
			return
		}
		d, err := time.ParseDuration(strings.TrimSpace(form.Get(field)))
		if err != nil {
			perr = fmt.Errorf("%s must be a duration like 15m, 12h, 720h", field)
			return
		}
		if d < lo || d > hi {
			perr = fmt.Errorf("%s must be between %s and %s", field, lo, hi)
			return
		}
		*dst = d
	}
	parse("token_ttl", minTokenTTL, maxTokenTTL, &next.TokenTTL)
	parse("refresh_token_ttl", minRefreshTTL, maxRefreshTTL, &next.RefreshTokenTTL)
	parse("lockout_duration", time.Second, 30*24*time.Hour, &next.LockoutDuration)
	parseSessionIdle("session_idle_timeout", form.Get("session_idle_timeout"), &next.SessionIdleTimeout, &perr)
	parse("session_lifetime", time.Minute, maxSessionTTL, &next.SessionLifetime)
	if perr != nil {
		s.renderSettings(w, r, http.StatusBadRequest, perr.Error(), "")
		return
	}

	// Integers.
	if v, err := strconv.Atoi(strings.TrimSpace(form.Get("max_failed_logins"))); err == nil && v >= 1 {
		next.MaxFailedLogins = v
	} else {
		s.renderSettings(w, r, http.StatusBadRequest, "Max failed logins must be a whole number ≥ 1.", "")
		return
	}
	if v, err := strconv.Atoi(strings.TrimSpace(form.Get("password_min_length"))); err == nil && v >= minPwLen {
		next.PasswordMinLength = v
	} else {
		s.renderSettings(w, r, http.StatusBadRequest, fmt.Sprintf("Password minimum length must be ≥ %d.", minPwLen), "")
		return
	}

	// Cross-field invariants.
	if next.RefreshTokenTTL < next.TokenTTL {
		s.renderSettings(w, r, http.StatusBadRequest, "Refresh token TTL must be ≥ the access token TTL.", "")
		return
	}
	if next.Issuer == "" || next.PublicURL == "" {
		s.renderSettings(w, r, http.StatusBadRequest, "Issuer and public URL are required.", "")
		return
	}

	if err := s.db.UpdateSettings(r.Context(), next.toModel()); err != nil {
		s.renderSettings(w, r, http.StatusInternalServerError, "Could not save settings.", "")
		return
	}
	s.settings.Reload(r.Context())
	s.audit(r, evtSettingsUpdated, auditEntry{actorUserID: actorID(r), success: true})
	http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
}

// handleAdminResetSettings restores the config-derived defaults.
func (s *Server) handleAdminResetSettings(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	if err := s.db.UpdateSettings(r.Context(), s.settings.Defaults().toModel()); err != nil {
		s.renderSettings(w, r, http.StatusInternalServerError, "Could not reset settings.", "")
		return
	}
	s.settings.Reload(r.Context())
	s.audit(r, evtSettingsUpdated, auditEntry{actorUserID: actorID(r), success: true, detail: "reset to config defaults"})
	http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
}

// parseSessionIdle accepts an empty/"0" value as "disabled" (0s).
func parseSessionIdle(field, raw string, dst *time.Duration, perr *error) {
	if *perr != nil {
		return
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "0" {
		*dst = 0
		return
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 || d > maxSessionTTL {
		*perr = fmt.Errorf("%s must be a non-negative duration (e.g. 30m) or 0 to disable", field)
		return
	}
	*dst = d
}
