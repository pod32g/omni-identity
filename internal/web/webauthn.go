package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/store"
)

// WebAuthn / passkeys. Standards-compliant registration and authentication via
// github.com/go-webauthn/webauthn; Omni owns the credential record for local
// and LDAP users alike. Policy (docs/PASSKEYS.md): registration asks for a
// discoverable credential with user verification "preferred"; at login, a
// passkey whose assertion carries the UV flag is treated as phishing-resistant
// multi-factor authentication (amr "webauthn user mfa") and skips TOTP; one
// without UV is a single factor and falls through to the user's TOTP step when
// they have one enabled.

const (
	webauthnCeremonyTTL = 5 * time.Minute
	maxWebAuthnBody     = 64 << 10
	amrPasskey          = "webauthn user"     // RFC 8176: user presence proven, via WebAuthn
	amrPasskeyUV        = "webauthn user mfa" // + user verification (PIN/biometric)
)

// webauthnRP caches the library instance for the current public URL.
type webauthnRP struct {
	mu   sync.Mutex
	key  string
	rp   *webauthn.WebAuthn
	err  error
	name string
}

var errPasskeysNeedHostname = errors.New("passkeys require the public URL to use a DNS host name (WebAuthn forbids IP addresses as RP IDs)")

// relyingParty returns the WebAuthn RP for the live public URL and product name.
func (s *Server) relyingParty() (*webauthn.WebAuthn, error) {
	pub := s.settings.Current().PublicURL
	name := s.mfaIssuer()
	s.wa.mu.Lock()
	defer s.wa.mu.Unlock()
	if s.wa.key == pub && s.wa.name == name {
		return s.wa.rp, s.wa.err
	}
	s.wa.key, s.wa.name = pub, name
	u, err := url.Parse(pub)
	if err != nil || u.Host == "" {
		s.wa.rp, s.wa.err = nil, errors.New("invalid public URL")
		return nil, s.wa.err
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		s.wa.rp, s.wa.err = nil, errPasskeysNeedHostname
		return nil, s.wa.err
	}
	s.wa.rp, s.wa.err = webauthn.New(&webauthn.Config{
		RPID:          host,
		RPDisplayName: name,
		RPOrigins:     []string{u.Scheme + "://" + u.Host},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		},
		AttestationPreference: protocol.PreferNoAttestation,
	})
	return s.wa.rp, s.wa.err
}

// passkeysEnabled reports whether the RP can be built (DNS host name).
func (s *Server) passkeysEnabled() bool {
	_, err := s.relyingParty()
	return err == nil
}

// webauthnUser adapts a model.User (+ its stored credentials) to webauthn.User.
type webauthnUser struct {
	u     *model.User
	creds []webauthn.Credential
	rows  []model.WebAuthnCredential
}

func (w *webauthnUser) WebAuthnID() []byte {
	b, _ := base64.RawURLEncoding.DecodeString(w.u.WebAuthnHandle)
	return b
}
func (w *webauthnUser) WebAuthnName() string                       { return w.u.Username }
func (w *webauthnUser) WebAuthnDisplayName() string                { return w.u.Username }
func (w *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

// loadWebAuthnUser builds the adapter, decoding stored credential records.
func (s *Server) loadWebAuthnUser(ctx context.Context, u *model.User) (*webauthnUser, error) {
	rows, err := s.db.ListWebAuthnCredentials(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	w := &webauthnUser{u: u, rows: rows}
	for _, row := range rows {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(row.Credential), &c); err != nil {
			return nil, err
		}
		w.creds = append(w.creds, c)
	}
	return w, nil
}

// ensureWebAuthnHandle assigns a random user handle on first registration.
func (s *Server) ensureWebAuthnHandle(ctx context.Context, u *model.User) error {
	if u.WebAuthnHandle != "" {
		return nil
	}
	handle := auth.RandomToken(32)
	if err := s.db.SetUserWebAuthnHandle(ctx, u.ID, handle); err != nil {
		// Lost a race with a concurrent registration: reload.
		fresh, gerr := s.db.GetUserByID(ctx, u.ID)
		if gerr != nil || fresh.WebAuthnHandle == "" {
			return err
		}
		u.WebAuthnHandle = fresh.WebAuthnHandle
		return nil
	}
	u.WebAuthnHandle = handle
	return nil
}

// jsonBody decodes a bounded JSON request body.
func jsonBody(w http.ResponseWriter, r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, maxWebAuthnBody)).Decode(v)
}

// jsonError writes an error in the same shape as the OAuth endpoints.
func jsonError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func (s *Server) newCeremony(ctx context.Context, userID, purpose string, sd *webauthn.SessionData, next, req string) (string, error) {
	raw, err := json.Marshal(sd)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	c := &model.WebAuthnCeremony{
		ID: auth.RandomToken(32), UserID: userID, Purpose: purpose, SessionData: string(raw),
		Next: next, Req: req, CreatedAt: now, ExpiresAt: now.Add(webauthnCeremonyTTL),
	}
	return c.ID, s.db.CreateWebAuthnCeremony(ctx, c)
}

func (s *Server) consumeCeremony(ctx context.Context, id, purpose string) (*model.WebAuthnCeremony, *webauthn.SessionData, error) {
	if id == "" {
		return nil, nil, store.ErrNotFound
	}
	c, err := s.db.ConsumeWebAuthnCeremony(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if c.Purpose != purpose {
		return nil, nil, store.ErrNotFound
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal([]byte(c.SessionData), &sd); err != nil {
		return nil, nil, err
	}
	return c, &sd, nil
}

// --- account: manage passkeys ---

type passkeyView struct {
	ID       string
	Name     string
	Created  string
	LastUsed string
	Synced   bool
}

type accountPasskeysPage struct {
	CSRFToken   string
	Me          *model.User
	Active      string
	Passkeys    []passkeyView
	Error       string
	Saved       string
	Unavailable string
}

func (s *Server) renderAccountPasskeys(w http.ResponseWriter, r *http.Request, status int, errMsg, saved string) {
	user := currentUser(r)
	rows, _ := s.db.ListWebAuthnCredentials(r.Context(), user.ID)
	page := accountPasskeysPage{
		CSRFToken: auth.CSRFToken(w, r, s.cookieSecure()),
		Me:        user, Active: "account", Error: errMsg, Saved: saved,
	}
	for _, c := range rows {
		v := passkeyView{ID: c.ID, Name: c.Name, Created: c.CreatedAt.Local().Format("2006-01-02"), LastUsed: "never", Synced: c.BackupEligible}
		if !c.LastUsedAt.IsZero() {
			v.LastUsed = humanSince(time.Now(), c.LastUsedAt)
		}
		page.Passkeys = append(page.Passkeys, v)
	}
	if _, err := s.relyingParty(); err != nil {
		page.Unavailable = err.Error()
	}
	s.tmpl.render(w, status, "account_passkeys", page)
}

func (s *Server) handleAccountPasskeys(w http.ResponseWriter, r *http.Request) {
	saved := ""
	if r.URL.Query().Get("saved") == "1" {
		saved = "Passkey added."
	}
	s.renderAccountPasskeys(w, r, http.StatusOK, "", saved)
}

// handlePasskeyRegisterBegin (JSON) starts a registration ceremony for the
// signed-in user.
func (s *Server) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := jsonBody(w, r, &body); err != nil || !auth.ValidateCSRFToken(r, body.CSRFToken) {
		jsonError(w, http.StatusForbidden, "invalid_request", "invalid CSRF token")
		return
	}
	rp, err := s.relyingParty()
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "passkeys_unavailable", err.Error())
		return
	}
	user := currentUser(r)
	if err := s.ensureWebAuthnHandle(r.Context(), user); err != nil {
		jsonError(w, http.StatusInternalServerError, "server_error", "could not prepare registration")
		return
	}
	wu, err := s.loadWebAuthnUser(r.Context(), user)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "server_error", "could not load credentials")
		return
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(wu.creds))
	for i := range wu.creds {
		exclude = append(exclude, wu.creds[i].Descriptor())
	}
	creation, sd, err := rp.BeginRegistration(wu,
		webauthn.WithExclusions(exclude),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
	)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "server_error", "could not start registration")
		return
	}
	id, err := s.newCeremony(r.Context(), user.ID, model.WebAuthnPurposeRegister, sd, "", "")
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "server_error", "could not start registration")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": id, "options": creation})
}

// handlePasskeyRegisterFinish (JSON) verifies the attestation and stores the
// credential.
func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var body struct {
		CSRFToken  string          `json:"csrf_token"`
		Ceremony   string          `json:"ceremony"`
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := jsonBody(w, r, &body); err != nil || !auth.ValidateCSRFToken(r, body.CSRFToken) {
		jsonError(w, http.StatusForbidden, "invalid_request", "invalid CSRF token")
		return
	}
	rp, err := s.relyingParty()
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "passkeys_unavailable", err.Error())
		return
	}
	user := currentUser(r)
	c, sd, err := s.consumeCeremony(r.Context(), body.Ceremony, model.WebAuthnPurposeRegister)
	if err != nil || c.UserID != user.ID {
		jsonError(w, http.StatusBadRequest, "invalid_request", "registration expired; start again")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body.Credential)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid_request", "malformed credential: "+err.Error())
		return
	}
	wu, err := s.loadWebAuthnUser(r.Context(), user)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "server_error", "could not load credentials")
		return
	}
	cred, err := rp.CreateCredential(wu, *sd, parsed)
	if err != nil {
		s.audit(r, evtPasskeyRegisterFailed, auditEntry{actorUserID: user.ID, username: user.Username, detail: safeErr(err)})
		jsonError(w, http.StatusBadRequest, "invalid_request", "the authenticator response was rejected")
		return
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "server_error", "could not store credential")
		return
	}
	name := truncate(strings.TrimSpace(body.Name), maxDeviceNameLength)
	if name == "" {
		name = "Passkey"
	}
	row := &model.WebAuthnCredential{
		ID:             base64.RawURLEncoding.EncodeToString(cred.ID),
		UserID:         user.ID,
		Name:           name,
		Credential:     string(raw),
		AAGUID:         base64.RawURLEncoding.EncodeToString(cred.Authenticator.AAGUID),
		BackupEligible: cred.Flags.BackupEligible,
		CreatedAt:      time.Now().UTC(),
	}
	if err := s.db.CreateWebAuthnCredential(r.Context(), row); err != nil {
		jsonError(w, http.StatusConflict, "invalid_request", "this passkey is already registered")
		return
	}
	s.audit(r, evtPasskeyRegistered, auditEntry{actorUserID: user.ID, username: user.Username, success: true,
		detail: "uv=" + boolStr(cred.Flags.UserVerified) + " backup_eligible=" + boolStr(cred.Flags.BackupEligible)})
	writeJSON(w, http.StatusCreated, map[string]any{"id": row.ID, "name": row.Name})
}

func (s *Server) handleAccountPasskeyDelete(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	user := currentUser(r)
	id := r.PathValue("id")
	if err := s.db.DeleteWebAuthnCredential(r.Context(), user.ID, id); err != nil {
		s.renderAccountPasskeys(w, r, http.StatusNotFound, "Passkey not found.", "")
		return
	}
	s.audit(r, evtPasskeyRemoved, auditEntry{actorUserID: user.ID, username: user.Username, success: true})
	s.renderAccountPasskeys(w, r, http.StatusOK, "", "Passkey removed.")
}

// handleAdminResetPasskeys removes every passkey of a user (lost authenticator).
func (s *Server) handleAdminResetPasskeys(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	id := r.PathValue("id")
	n, err := s.db.DeleteWebAuthnCredentialsForUser(r.Context(), id)
	if err != nil {
		s.userActionError(w, r, http.StatusBadRequest, "Could not remove passkeys.")
		return
	}
	target, _ := s.db.GetUserByID(r.Context(), id)
	username := ""
	if target != nil {
		username = target.Username
	}
	s.audit(r, evtPasskeyReset, auditEntry{actorUserID: actorID(r), username: username, success: true,
		detail: "id=" + id + " removed=" + itoa(int(n))})
	s.userActionDone(w, r, id)
}

// --- login with a passkey ---

// handlePasskeyLoginBegin (JSON) starts an authentication ceremony. With a
// username it lists that user's credentials; without one (or for an unknown
// user / one without passkeys, to avoid enumeration) it asks the browser for a
// discoverable credential.
func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var body struct {
		CSRFToken string `json:"csrf_token"`
		Username  string `json:"username"`
	}
	if err := jsonBody(w, r, &body); err != nil || !auth.ValidateCSRFToken(r, body.CSRFToken) {
		jsonError(w, http.StatusForbidden, "invalid_request", "invalid CSRF token")
		return
	}
	policy := s.settings.Current()
	if !s.loginIPRate.Allowed(clientIP(r), policy.LoginIPMaxAttempts, policy.RateLimitWindow) {
		jsonError(w, http.StatusTooManyRequests, "rate_limited", "Too many sign-in attempts. Please wait a few minutes and try again.")
		return
	}
	rp, err := s.relyingParty()
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "passkeys_unavailable", err.Error())
		return
	}
	var (
		assertion *protocol.CredentialAssertion
		sd        *webauthn.SessionData
		userID    string
	)
	username := strings.TrimSpace(body.Username)
	if len(username) > policy.MaxLoginUsernameBytes {
		username = ""
	}
	if username != "" {
		if u, err := s.db.GetUserByUsername(r.Context(), username); err == nil && !u.Disabled {
			if wu, err := s.loadWebAuthnUser(r.Context(), u); err == nil && len(wu.creds) > 0 {
				assertion, sd, err = rp.BeginLogin(wu, webauthn.WithUserVerification(protocol.VerificationPreferred))
				if err == nil {
					userID = u.ID
				}
			}
		}
	}
	if assertion == nil {
		assertion, sd, err = rp.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationPreferred))
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "server_error", "could not start sign-in")
			return
		}
	}
	id, err := s.newCeremony(r.Context(), userID, model.WebAuthnPurposeLogin, sd, "", "")
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "server_error", "could not start sign-in")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": id, "options": assertion})
}

// handlePasskeyLoginFinish (JSON) verifies the assertion, applies the MFA
// policy, and either issues a session or parks a TOTP challenge. It answers
// with the URL the browser should go to next.
func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var body struct {
		CSRFToken  string          `json:"csrf_token"`
		Ceremony   string          `json:"ceremony"`
		Credential json.RawMessage `json:"credential"`
		Next       string          `json:"next"`
		Req        string          `json:"req"`
	}
	if err := jsonBody(w, r, &body); err != nil || !auth.ValidateCSRFToken(r, body.CSRFToken) {
		jsonError(w, http.StatusForbidden, "invalid_request", "invalid CSRF token")
		return
	}
	policy := s.settings.Current()
	ip := clientIP(r)
	fail := func(status int, detail string) {
		s.loginIPRate.Fail(ip, policy.RateLimitWindow)
		s.metrics.recordLogin("passkey", "failure")
		s.audit(r, evtPasskeyLoginFailed, auditEntry{detail: detail})
		jsonError(w, status, "invalid_grant", "Passkey sign-in failed.")
	}
	rp, err := s.relyingParty()
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "passkeys_unavailable", err.Error())
		return
	}
	c, sd, err := s.consumeCeremony(r.Context(), body.Ceremony, model.WebAuthnPurposeLogin)
	if err != nil {
		fail(http.StatusBadRequest, "ceremony missing or expired")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Credential)
	if err != nil {
		fail(http.StatusBadRequest, "malformed assertion")
		return
	}

	var (
		wu   *webauthnUser
		cred *webauthn.Credential
	)
	if c.UserID != "" {
		u, err := s.db.GetUserByID(r.Context(), c.UserID)
		if err != nil {
			fail(http.StatusUnauthorized, "user vanished")
			return
		}
		if wu, err = s.loadWebAuthnUser(r.Context(), u); err != nil {
			fail(http.StatusUnauthorized, "credentials unavailable")
			return
		}
		cred, err = rp.ValidateLogin(wu, *sd, parsed)
		if err != nil {
			fail(http.StatusUnauthorized, safeErr(err))
			return
		}
	} else {
		handler := func(rawID, userHandle []byte) (webauthn.User, error) {
			u, err := s.db.GetUserByWebAuthnHandle(r.Context(), base64.RawURLEncoding.EncodeToString(userHandle))
			if err != nil {
				return nil, errors.New("unknown user handle")
			}
			loaded, err := s.loadWebAuthnUser(r.Context(), u)
			if err != nil {
				return nil, err
			}
			wu = loaded
			return loaded, nil
		}
		_, cred, err = rp.ValidatePasskeyLogin(handler, *sd, parsed)
		if err != nil || wu == nil {
			fail(http.StatusUnauthorized, safeErr(err))
			return
		}
	}
	user := wu.u
	if user.Disabled {
		fail(http.StatusUnauthorized, "disabled account")
		return
	}
	if cred.Authenticator.CloneWarning {
		// Sign counter went backwards: a cloned authenticator may exist.
		s.audit(r, evtPasskeyLoginFailed, auditEntry{actorUserID: user.ID, username: user.Username, detail: "clone warning (sign counter regressed)"})
		s.metrics.recordLogin("passkey", "failure")
		jsonError(w, http.StatusUnauthorized, "invalid_grant", "This passkey could not be trusted (sign counter regressed). Remove and re-register it.")
		return
	}
	// Persist the updated counter/flags and last-used time.
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	if raw, err := json.Marshal(cred); err == nil {
		_ = s.db.UpdateWebAuthnCredential(r.Context(), credID, string(raw), time.Now().UTC())
	}

	s.loginIPRate.Reset(ip)
	uv := parsed.Response.AuthenticatorData.Flags.UserVerified()
	amr := amrPasskey
	if uv {
		amr = amrPasskeyUV
	}
	next := safeNext(body.Next)
	reqID := body.Req

	// Policy: a passkey without user verification is one factor; users with
	// TOTP enabled still complete it. A UV passkey is already multi-factor.
	if !uv && user.MFAEnabled {
		if err := s.createMFAChallenge(w, r, user, next, reqID, amr); err != nil {
			jsonError(w, http.StatusInternalServerError, "server_error", "could not start verification")
			return
		}
		s.audit(r, evtPasskeyLoginSuccess, auditEntry{actorUserID: user.ID, username: user.Username, success: true, detail: "uv=false; totp required"})
		writeJSON(w, http.StatusOK, map[string]string{"redirect": "/login/mfa"})
		return
	}

	if _, err := s.sessions.Issue(w, r, user.ID, amr); err != nil {
		jsonError(w, http.StatusInternalServerError, "server_error", "could not create session")
		return
	}
	s.metrics.recordLogin("passkey", "success")
	s.audit(r, evtLoginSuccess, auditEntry{actorUserID: user.ID, username: user.Username, success: true, detail: "passkey uv=" + boolStr(uv)})

	dest := redirectAfterLogin(user)
	switch {
	case reqID != "":
		// The parked OIDC request continues via GET /login?req=… now that a
		// session exists (handleLoginForm resumes it).
		dest = "/login?req=" + url.QueryEscape(reqID)
	case next != "":
		dest = next
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": dest})
}

// safeErr truncates a library error for the audit detail column.
func safeErr(err error) string {
	if err == nil {
		return ""
	}
	return truncate(err.Error(), 200)
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// handleStatic serves the embedded browser helper. CSP is script-src 'self',
// so passkey JavaScript must come from this origin rather than inline.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	f, err := staticFS.Open("static/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	if strings.HasSuffix(name, ".js") {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = io.Copy(w, f)
}
