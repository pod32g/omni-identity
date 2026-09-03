package web

import (
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/oidc"
	"github.com/pod32g/omni-identity/internal/store"
)

// RFC 8628 parameters.
const (
	deviceCodeTTL           = 10 * time.Minute
	deviceCodeInterval      = 5 // seconds between polls
	deviceCodeMaxAttempts   = 10
	deviceGrantMaxPerWindow = 60                     // device_authorization requests per IP per rate-limit window
	userCodeAlphabet        = "BCDFGHJKLMNPQRSTVWXZ" // RFC 8628 §6.1: no vowels, no ambiguous glyphs
	userCodeLength          = 8
	maxDeviceNameLength     = 64
	maxDevicePlatformField  = 32
)

var errDPoPReplay = errors.New("dpop: proof jti already used")

// deviceAuthorizationResponse is the RFC 8628 §3.2 response body.
type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// handleDeviceAuthorization implements RFC 8628 §3.1. When the request carries
// a device token (an enrolled device asking for a user login), the pending
// grant is bound to that device so the resulting user tokens carry device
// claims (docs/DEVICE-IDENTITY-ARCHITECTURE.md §7).
func (s *Server) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	client, ok := s.authenticateClient(r)
	if !ok {
		oauthClientAuthError(w)
		return
	}
	// Each request parks a row for up to 10 minutes; bound how many one source
	// can create (the sweeper reclaims them, this keeps the burst small).
	policy := s.settings.Current()
	if !s.deviceGrantRate.Allowed(clientIP(r), deviceGrantMaxPerWindow, policy.RateLimitWindow) {
		oauthError(w, http.StatusTooManyRequests, "slow_down", "too many device authorization requests from this address")
		return
	}
	s.deviceGrantRate.Fail(clientIP(r), policy.RateLimitWindow)

	scope := strings.TrimSpace(r.PostFormValue("scope"))
	if scope == "" {
		scope = oidc.ScopeOpenID
	}
	if !oidc.ScopesSubset(oidc.SplitScope(scope), client.AllowedScopes) {
		oauthError(w, http.StatusBadRequest, "invalid_scope", "requested scope is not allowed for this client")
		return
	}

	// Optional: an enrolled device authenticating the request.
	var dev *model.Device
	if r.Header.Get("Authorization") != "" {
		d, err := s.authenticateDeviceRequest(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
			oauthError(w, http.StatusUnauthorized, "invalid_token", "device authentication failed")
			return
		}
		dev = d
	}

	now := time.Now().UTC()
	rawCode := auth.RandomToken(32)
	dc := &model.DeviceCode{
		ID:             uuid.NewString(),
		DeviceCodeHash: auth.HashToken(rawCode),
		ClientID:       client.ClientID,
		Scope:          scope,
		DeviceName:     truncate(strings.TrimSpace(r.PostFormValue("device_name")), maxDeviceNameLength),
		DevicePlatform: truncate(strings.TrimSpace(r.PostFormValue("device_platform")), maxDevicePlatformField),
		Status:         model.DeviceCodePending,
		CreatedAt:      now,
		ExpiresAt:      now.Add(deviceCodeTTL),
	}
	if dev != nil {
		dc.DeviceID = dev.ID
		dc.DeviceName = dev.Name
		dc.DevicePlatform = dev.Platform
	}
	// Retry on the (astronomically unlikely) user-code collision.
	var err error
	for i := 0; i < 3; i++ {
		dc.UserCode = newUserCode()
		if err = s.db.CreateDeviceCode(r.Context(), dc); err == nil {
			break
		}
	}
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not start device authorization")
		return
	}

	detail := "scope=" + scope
	if dev != nil {
		detail += " device=" + dev.ID
	}
	s.audit(r, evtDeviceGrantRequested, auditEntry{clientID: client.ClientID, success: true, detail: detail})
	s.metrics.recordDeviceGrant("requested")

	base := strings.TrimRight(s.settings.Current().PublicURL, "/")
	writeJSON(w, http.StatusOK, deviceAuthorizationResponse{
		DeviceCode:              rawCode,
		UserCode:                formatUserCode(dc.UserCode),
		VerificationURI:         base + "/device",
		VerificationURIComplete: base + "/device?user_code=" + formatUserCode(dc.UserCode),
		ExpiresIn:               int(deviceCodeTTL.Seconds()),
		Interval:                deviceCodeInterval,
	})
}

// grantDeviceCode implements RFC 8628 §3.4/§3.5: the client polls with its
// device code until the user approves or denies on /device.
func (s *Server) grantDeviceCode(w http.ResponseWriter, r *http.Request) {
	client, ok := s.authenticateClient(r)
	if !ok {
		oauthClientAuthError(w)
		return
	}
	raw := r.PostFormValue("device_code")
	if raw == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "missing device_code")
		return
	}
	dc, err := s.db.GetDeviceCodeByHash(r.Context(), auth.HashToken(raw))
	if err != nil || dc.ClientID != client.ClientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid device_code")
		return
	}
	now := time.Now().UTC()
	if now.After(dc.ExpiresAt) {
		s.metrics.recordDeviceGrant("expired")
		oauthError(w, http.StatusBadRequest, "expired_token", "the device code has expired")
		return
	}
	if !dc.LastPolledAt.IsZero() && now.Sub(dc.LastPolledAt) < time.Duration(deviceCodeInterval)*time.Second {
		_ = s.db.MarkDeviceCodePolled(r.Context(), dc.ID, now)
		oauthError(w, http.StatusBadRequest, "slow_down", "polling too frequently")
		return
	}
	_ = s.db.MarkDeviceCodePolled(r.Context(), dc.ID, now)

	switch dc.Status {
	case model.DeviceCodePending:
		oauthError(w, http.StatusBadRequest, "authorization_pending", "the user has not yet approved the request")
		return
	case model.DeviceCodeDenied:
		oauthError(w, http.StatusBadRequest, "access_denied", "the user denied the request")
		return
	case model.DeviceCodeApproved:
		// continue
	default:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "device code already used")
		return
	}

	// A device-bound grant must be redeemed by the same enrolled device.
	tc := tokenContext{amr: dc.AMR, jkt: dpopJKT(r)}
	if dc.DeviceID != "" {
		dev, err := s.authenticateDeviceRequest(r)
		if err != nil || dev.ID != dc.DeviceID {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "device authentication required for this grant")
			return
		}
		if dev.OwnerOnly && dev.OwnerUserID != dc.UserID {
			oauthError(w, http.StatusBadRequest, "access_denied", "this device only allows its owner to sign in")
			return
		}
		tc.device = dev
	}

	user, err := s.db.GetUserByID(r.Context(), dc.UserID)
	if err != nil || user.Disabled {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "user is not available")
		return
	}
	consumed, err := s.db.ConsumeDeviceCode(r.Context(), dc.ID)
	if err != nil || !consumed {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "device code already used")
		return
	}

	resp, err := s.buildAccessAndID(client, user, dc.Scope, "", dc.AuthTime, tc)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not issue tokens")
		return
	}
	if oidc.HasScope(dc.Scope, oidc.ScopeOfflineAccess) {
		rawRT, newRT := s.newRefreshToken(client, user, dc.Scope, dc.AuthTime, "", tc)
		if err := s.db.CreateRefreshToken(r.Context(), newRT); err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", "could not issue refresh token")
			return
		}
		resp.RefreshToken = rawRT
	}
	s.recordTokenMetrics(resp)
	s.metrics.recordDeviceGrant("issued")
	detail := "device_code"
	if tc.device != nil {
		detail += " device=" + tc.device.ID
	}
	s.audit(r, evtTokenIssued, auditEntry{actorUserID: user.ID, username: user.Username, clientID: client.ClientID, success: true, detail: detail})
	writeJSON(w, http.StatusOK, resp)
}

// --- /device: the user-facing verification and approval page ---

type devicePage struct {
	CSRFToken string
	Me        *model.User
	Active    string
	Stage     string // enter | confirm | done
	Error     string
	Message   string
	UserCode  string
	AppName   string
	Enroll    bool // the grant requests device:enroll
	// Display metadata of the requesting endpoint (unenrolled: self-reported;
	// enrolled: from the device record).
	DeviceName     string
	DevicePlatform string
	Enrolled       bool   // the request was authenticated by an enrolled device
	OwnerName      string // owner of that enrolled device
	OwnerIsMe      bool
	OwnerOnly      bool // the device refuses sign-ins by anyone but its owner
}

func (s *Server) handleDeviceForm(w http.ResponseWriter, r *http.Request) {
	s.renderDevice(w, r, http.StatusOK, devicePage{
		Stage:    "enter",
		UserCode: formatUserCode(normalizeUserCode(r.URL.Query().Get("user_code"))),
	})
}

func (s *Server) renderDevice(w http.ResponseWriter, r *http.Request, status int, p devicePage) {
	p.CSRFToken = auth.CSRFToken(w, r, s.cookieSecure())
	p.Me = currentUser(r)
	p.Active = "account"
	s.tmpl.render(w, status, "device", p)
}

// lookupUserCode resolves a submitted user code to its pending grant, applying
// a per-IP guessing budget. Renders an error page and returns nil on failure.
func (s *Server) lookupUserCode(w http.ResponseWriter, r *http.Request) *model.DeviceCode {
	policy := s.settings.Current()
	ip := clientIP(r)
	if !s.deviceCodeRate.Allowed(ip, deviceCodeMaxAttempts, policy.RateLimitWindow) {
		s.renderDevice(w, r, http.StatusTooManyRequests, devicePage{Stage: "enter",
			Error: "Too many attempts. Please wait a few minutes and try again."})
		return nil
	}
	code := normalizeUserCode(r.PostFormValue("user_code"))
	dc, err := s.db.GetPendingDeviceCodeByUserCode(r.Context(), code)
	if err != nil {
		s.deviceCodeRate.Fail(ip, policy.RateLimitWindow)
		msg := "That code was not recognized. Check it and try again."
		if errors.Is(err, store.ErrNotFound) && code != "" {
			msg = "That code is invalid, expired, or already used. Start again on the device."
		}
		s.renderDevice(w, r, http.StatusBadRequest, devicePage{Stage: "enter", Error: msg, UserCode: formatUserCode(code)})
		return nil
	}
	return dc
}

// pageForGrant fills the confirmation view for a pending grant.
func (s *Server) pageForGrant(r *http.Request, dc *model.DeviceCode) devicePage {
	p := devicePage{
		Stage:          "confirm",
		UserCode:       formatUserCode(dc.UserCode),
		Enroll:         oidc.HasScope(dc.Scope, oidc.ScopeDeviceEnroll),
		DeviceName:     dc.DeviceName,
		DevicePlatform: dc.DevicePlatform,
	}
	if c, err := s.db.GetClient(r.Context(), dc.ClientID); err == nil {
		p.AppName = c.Label()
	} else {
		p.AppName = dc.ClientID
	}
	if dc.DeviceID != "" {
		p.Enrolled = true
		if dev, err := s.db.GetDevice(r.Context(), dc.DeviceID); err == nil {
			p.DeviceName, p.DevicePlatform, p.OwnerOnly = dev.Name, dev.Platform, dev.OwnerOnly
			if owner, err := s.db.GetUserByID(r.Context(), dev.OwnerUserID); err == nil {
				p.OwnerName = owner.Username
				if me := currentUser(r); me != nil {
					p.OwnerIsMe = me.ID == owner.ID
				}
			}
		}
	}
	return p
}

// handleDeviceLookup (POST /device) validates the code and shows what is being
// approved. Nothing is granted yet.
func (s *Server) handleDeviceLookup(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	dc := s.lookupUserCode(w, r)
	if dc == nil {
		return
	}
	s.renderDevice(w, r, http.StatusOK, s.pageForGrant(r, dc))
}

// handleDeviceConfirm (POST /device/confirm) records the user's decision.
func (s *Server) handleDeviceConfirm(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	dc := s.lookupUserCode(w, r)
	if dc == nil {
		return
	}
	user := currentUser(r)
	sess := currentSession(r)
	enroll := oidc.HasScope(dc.Scope, oidc.ScopeDeviceEnroll)
	entry := auditEntry{actorUserID: user.ID, username: user.Username, clientID: dc.ClientID,
		detail: "device_code=" + dc.ID}
	if dc.DeviceID != "" {
		entry.detail += " device=" + dc.DeviceID
		// Owner-only devices accept sign-ins from their owner alone.
		if dev, err := s.db.GetDevice(r.Context(), dc.DeviceID); err == nil && dev.OwnerOnly && dev.OwnerUserID != user.ID {
			_ = s.db.DenyDeviceCode(r.Context(), dc.ID)
			entry.detail += " owner_only"
			s.audit(r, evtDeviceLoginDenied, entry)
			s.metrics.recordDeviceGrant("denied")
			s.renderDevice(w, r, http.StatusForbidden, devicePage{Stage: "done",
				Message: "This device only allows its owner to sign in. The request was denied."})
			return
		}
	}

	if r.PostFormValue("action") != "allow" {
		_ = s.db.DenyDeviceCode(r.Context(), dc.ID)
		evt := evtDeviceLoginDenied
		if enroll {
			evt = evtDeviceEnrollDenied
			s.metrics.recordDeviceEnrollment("denied")
		}
		s.metrics.recordDeviceGrant("denied")
		s.audit(r, evt, entry)
		s.renderDevice(w, r, http.StatusOK, devicePage{Stage: "done",
			Message: "Request denied. You can close this page."})
		return
	}

	amr, authTime := "", time.Now().UTC()
	if sess != nil {
		amr = sess.AMR
		if !sess.CreatedAt.IsZero() {
			authTime = sess.CreatedAt
		}
	}
	if err := s.db.ApproveDeviceCode(r.Context(), dc.ID, user.ID, amr, authTime); err != nil {
		s.renderDevice(w, r, http.StatusBadRequest, devicePage{Stage: "enter",
			Error: "That code is no longer pending. Start again on the device."})
		return
	}
	entry.success = true
	evt := evtDeviceLoginApproved
	msg := "Approved. You can return to the device — it will finish signing in on its own."
	if enroll {
		evt = evtDeviceEnrollStarted
		msg = "Approved. Return to the device to finish enrolling it. It will appear under My Devices once done."
	}
	s.metrics.recordDeviceGrant("approved")
	s.audit(r, evt, entry)
	s.renderDevice(w, r, http.StatusOK, devicePage{Stage: "done", Message: msg})
}

// --- helpers ---

func newUserCode() string {
	b := make([]byte, userCodeLength)
	if _, err := rand.Read(b); err != nil {
		panic("device code: crypto/rand failed: " + err.Error())
	}
	out := make([]byte, userCodeLength)
	for i, v := range b {
		out[i] = userCodeAlphabet[int(v)%len(userCodeAlphabet)]
	}
	return string(out)
}

// normalizeUserCode canonicalizes user input: uppercase, letters only.
func normalizeUserCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if r >= 'A' && r <= 'Z' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// formatUserCode renders XXXX-XXXX for display.
func formatUserCode(code string) string {
	if len(code) != userCodeLength {
		return code
	}
	return code[:4] + "-" + code[4:]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
