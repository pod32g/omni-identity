package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pod32g/omni-identity/internal/config"
)

// settingBounds caps the editable durations to sane ranges.
const (
	minTokenTTL                 = 1 * time.Minute
	maxTokenTTL                 = 24 * time.Hour
	minRefreshTTL               = 5 * time.Minute
	maxRefreshTTL               = 365 * 24 * time.Hour
	maxSessionTTL               = 90 * 24 * time.Hour
	minRateLimitWindow          = time.Second
	maxRateLimitWindow          = 24 * time.Hour
	minPwLen                    = 8
	minLoginUsernameBytes       = 64
	maxLoginUsernameBytesLimit  = 4096
	minLoginPasswordBytes       = 64
	maxLoginPasswordBytesLimit  = 1024 * 1024
	minPasswordVerifyConcurrent = 1
	maxPasswordVerifyConcurrent = 64
	minLogoKiB                  = 16
	maxLogoKiB                  = 5 * 1024
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
	next.RequireUpper = form.Get("require_upper") == "on"
	next.RequireLower = form.Get("require_lower") == "on"
	next.RequireNumber = form.Get("require_number") == "on"
	next.RequireSymbol = form.Get("require_symbol") == "on"
	next.AllowLoopbackHTTPRedirect = form.Get("allow_loopback_http_redirects") == "on"
	// Directory write management is toggled via its own endpoint
	// (/admin/settings/directory), so it is preserved here as-is (next starts from
	// the current view) rather than read from this form.

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
	parse("rate_limit_window", minRateLimitWindow, maxRateLimitWindow, &next.RateLimitWindow)
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
	if v, ok := parseIntRange(form.Get("login_ip_max_attempts"), 1, 100000); ok {
		next.LoginIPMaxAttempts = v
	} else {
		s.renderSettings(w, r, http.StatusBadRequest, "IP max failed logins must be a whole number ≥ 1.", "")
		return
	}
	if v, ok := parseIntRange(form.Get("password_verify_concurrency"), minPasswordVerifyConcurrent, maxPasswordVerifyConcurrent); ok {
		next.PasswordVerifyConcurrency = v
	} else {
		s.renderSettings(w, r, http.StatusBadRequest, fmt.Sprintf("Password verification concurrency must be between %d and %d.", minPasswordVerifyConcurrent, maxPasswordVerifyConcurrent), "")
		return
	}
	if v, ok := parseIntRange(form.Get("max_login_username_bytes"), minLoginUsernameBytes, maxLoginUsernameBytesLimit); ok {
		next.MaxLoginUsernameBytes = v
	} else {
		s.renderSettings(w, r, http.StatusBadRequest, fmt.Sprintf("Username byte cap must be between %d and %d.", minLoginUsernameBytes, maxLoginUsernameBytesLimit), "")
		return
	}
	if v, ok := parseIntRange(form.Get("max_login_password_bytes"), minLoginPasswordBytes, maxLoginPasswordBytesLimit); ok {
		next.MaxLoginPasswordBytes = v
	} else {
		s.renderSettings(w, r, http.StatusBadRequest, fmt.Sprintf("Password byte cap must be between %d and %d.", minLoginPasswordBytes, maxLoginPasswordBytesLimit), "")
		return
	}
	if v, ok := parseIntRange(form.Get("max_logo_kib"), minLogoKiB, maxLogoKiB); ok {
		next.MaxLogoBytes = v * 1024
	} else {
		s.renderSettings(w, r, http.StatusBadRequest, fmt.Sprintf("Logo upload size must be between %d and %d KiB.", minLogoKiB, maxLogoKiB), "")
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
	issuer, _, err := config.NormalizePublicURL("issuer", next.Issuer, s.cfg.Server.AllowInsecureHTTP)
	if err != nil {
		s.renderSettings(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	publicURL, parsedPublicURL, err := config.NormalizePublicURL("public URL", next.PublicURL, s.cfg.Server.AllowInsecureHTTP)
	if err != nil {
		s.renderSettings(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	next.Issuer = issuer
	next.PublicURL = publicURL
	if parsedPublicURL.Scheme == "https" && !next.CookieSecure {
		s.renderSettings(w, r, http.StatusBadRequest, "Cookie Secure must be enabled when the public URL uses HTTPS.", "")
		return
	}
	if parsedPublicURL.Scheme == "http" && next.CookieSecure {
		s.renderSettings(w, r, http.StatusBadRequest, "Cookie Secure must be disabled when the public URL uses HTTP.", "")
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

// handleAdminUpdateDirectoryManagement flips just the live LDAP write-management
// toggle. It is its own focused endpoint (and form) so it never has to satisfy
// the full system-settings validation, and so the control can live in the
// read-only System tab without being part of that big form.
func (s *Server) handleAdminUpdateDirectoryManagement(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	// Only honored when a write-capable bind exists (the control is hidden
	// otherwise; this also defends against a forged post).
	enable := r.PostFormValue("ldap_manage_enabled") == "on" && s.directoryWriteCapable()

	m, err := s.db.GetSettings(r.Context())
	if err != nil {
		s.renderSettings(w, r, http.StatusInternalServerError, "Could not load settings.", "")
		return
	}
	m.LDAPManageEnabled = enable
	if err := s.db.UpdateSettings(r.Context(), m); err != nil {
		s.renderSettings(w, r, http.StatusInternalServerError, "Could not save settings.", "")
		return
	}
	s.settings.Reload(r.Context())
	s.audit(r, evtSettingsUpdated, auditEntry{actorUserID: actorID(r), success: true, detail: "ldap_manage_enabled=" + boolStr(enable)})
	http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
}

func parseIntRange(raw string, lo, hi int) (int, bool) {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v < lo || v > hi {
		return 0, false
	}
	return v, true
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
