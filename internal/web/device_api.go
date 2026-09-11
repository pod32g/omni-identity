package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/oidc"
	"github.com/pod32g/omni-identity/internal/pop"
	"github.com/pod32g/omni-identity/internal/tokens"
)

const maxDeviceAPIBody = 64 << 10

// apiError writes a JSON error in the RFC 6749/6750 shape used by the token
// endpoint, so clients need one error parser.
func apiError(w http.ResponseWriter, status int, code, desc string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `DPoP error="`+code+`"`)
	}
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// authorizationToken splits "Authorization: <scheme> <token>".
func authorizationToken(r *http.Request) (scheme, token string) {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	i := strings.IndexByte(h, ' ')
	if i < 0 {
		return "", ""
	}
	return h[:i], strings.TrimSpace(h[i+1:])
}

// resourceToken authenticates a request to a DPoP-aware resource: it verifies
// the JWT and, when the token is bound (cnf.jkt), requires a valid DPoP proof
// from that key covering this request and the token (ath). Unbound tokens are
// accepted as plain bearer tokens. The DPoP scheme is accepted alongside
// Bearer for compatibility.
func (s *Server) resourceToken(r *http.Request) (*tokens.VerifiedToken, string, error) {
	scheme, raw := authorizationToken(r)
	if raw == "" || (!strings.EqualFold(scheme, "DPoP") && !strings.EqualFold(scheme, "Bearer")) {
		return nil, "", errors.New("missing bearer token")
	}
	vt, err := s.issuer.Verify(raw)
	if err != nil {
		return nil, "", errors.New("invalid or expired token")
	}
	if vt.JKT != "" {
		// The token endpoint verifies (and consumes) the request's proof before
		// dispatching grants; reuse it there instead of treating the second
		// verification as a replay. It must still be bound to this token (ath).
		proof, ok := r.Context().Value(dpopCtxKey{}).(*pop.Proof)
		if ok && proof != nil {
			if proof.ATH != pop.AccessTokenHash(raw) {
				return nil, "", errors.New("dpop: proof is not bound to the presented token")
			}
		} else {
			p, err := s.verifyDPoP(r, r.Header.Get("DPoP"), raw)
			if err != nil {
				return nil, "", err
			}
			proof = p
		}
		if proof.JKT != vt.JKT {
			return nil, "", errors.New("dpop: proof key does not match the token binding")
		}
	}
	return vt, raw, nil
}

// authenticateDeviceRequest resolves the active enrolled device that
// authenticated this request with a device token (docs §6).
func (s *Server) authenticateDeviceRequest(r *http.Request) (*model.Device, error) {
	vt, _, err := s.resourceToken(r)
	if err != nil {
		return nil, err
	}
	if !vt.IsDeviceToken() {
		return nil, errors.New("not a device token")
	}
	dev, err := s.db.GetDevice(r.Context(), vt.Subject)
	if err != nil || !dev.IsActive() {
		return nil, errors.New("device is not active")
	}
	return dev, nil
}

// deviceJSON is the wire representation of a device.
type deviceJSON struct {
	ID           string `json:"device_id"`
	Name         string `json:"name"`
	Hostname     string `json:"hostname"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Fingerprint  string `json:"fingerprint"`
	Algorithm    string `json:"public_key_algorithm"`
	Status       string `json:"status"`
	TrustLevel   string `json:"trust_level"`
	KeyBackend   string `json:"key_backend,omitempty"`
	Posture      any    `json:"posture,omitempty"`
	PostureAt    string `json:"posture_at,omitempty"`
	OwnerSub     string `json:"owner_sub"`
	OwnerName    string `json:"owner_username,omitempty"`
	OwnerOnly    bool   `json:"owner_only"`
	EnrolledAt   string `json:"enrolled_at,omitempty"`
	LastSeenAt   string `json:"last_seen_at,omitempty"`
	RevokedAt    string `json:"revoked_at,omitempty"`
}

func deviceToJSON(d *model.Device, ownerName string) deviceJSON {
	j := deviceJSON{
		ID: d.ID, Name: d.Name, Hostname: d.Hostname, Platform: d.Platform, Architecture: d.Architecture,
		Fingerprint: d.Fingerprint, Algorithm: d.PublicKeyAlgorithm, Status: d.Status, TrustLevel: d.TrustLevel,
		KeyBackend: d.KeyBackend, OwnerSub: d.OwnerUserID, OwnerName: ownerName, OwnerOnly: d.OwnerOnly,
	}
	if p := parsePosture(d.Posture); p != nil {
		j.Posture = p
	}
	if !d.PostureAt.IsZero() {
		j.PostureAt = d.PostureAt.UTC().Format(time.RFC3339)
	}
	if !d.EnrolledAt.IsZero() {
		j.EnrolledAt = d.EnrolledAt.UTC().Format(time.RFC3339)
	}
	if !d.LastSeenAt.IsZero() {
		j.LastSeenAt = d.LastSeenAt.UTC().Format(time.RFC3339)
	}
	if !d.RevokedAt.IsZero() {
		j.RevokedAt = d.RevokedAt.UTC().Format(time.RFC3339)
	}
	return j
}

// handleEnrollDevice implements POST /api/v1/devices (docs §5.2 step 5). The
// caller presents a DPoP-bound access token with the device:enroll scope; the
// DPoP proof's key becomes the device's registered public key.
func (s *Server) handleEnrollDevice(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fail := func(status int, code, desc, detail string) {
		s.metrics.recordDeviceEnrollment("failure")
		s.audit(r, evtDeviceEnrollFailed, auditEntry{detail: detail})
		apiError(w, status, code, desc)
	}

	scheme, raw := authorizationToken(r)
	if raw == "" || (!strings.EqualFold(scheme, "DPoP") && !strings.EqualFold(scheme, "Bearer")) {
		fail(http.StatusUnauthorized, "invalid_token", "missing access token", "no token")
		return
	}
	vt, err := s.issuer.Verify(raw)
	if err != nil || !vt.IsAccessToken() {
		fail(http.StatusUnauthorized, "invalid_token", "invalid or expired access token", "bad token")
		return
	}
	if !oidc.HasScope(vt.Scope, oidc.ScopeDeviceEnroll) {
		fail(http.StatusForbidden, "insufficient_scope", "the device:enroll scope is required", "missing scope")
		return
	}
	// The token MUST be DPoP-bound: the key it is bound to is the device key.
	if vt.JKT == "" {
		fail(http.StatusUnauthorized, "invalid_token", "enrollment requires a DPoP-bound access token", "unbound token")
		return
	}
	proof, err := s.verifyDPoP(r, r.Header.Get("DPoP"), raw)
	if err != nil {
		fail(http.StatusUnauthorized, "invalid_dpop_proof", err.Error(), "bad proof")
		return
	}
	if proof.JKT != vt.JKT {
		// Public-key substitution attempt: the proof key is not the bound key.
		fail(http.StatusUnauthorized, "invalid_dpop_proof", "proof key does not match the token binding", "key substitution")
		return
	}

	user, err := s.db.GetUserByID(r.Context(), vt.Subject)
	if err != nil || user.Disabled {
		fail(http.StatusUnauthorized, "invalid_token", "user is not available", "user unavailable")
		return
	}

	var body struct {
		KeyBackend   string `json:"key_backend"`
		Name         string `json:"name"`
		Hostname     string `json:"hostname"`
		Platform     string `json:"platform"`
		Architecture string `json:"architecture"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDeviceAPIBody)).Decode(&body); err != nil {
		fail(http.StatusBadRequest, "invalid_request", "malformed JSON body", "bad body")
		return
	}
	body.Hostname = truncate(strings.TrimSpace(body.Hostname), 253)
	body.Name = truncate(strings.TrimSpace(body.Name), maxDeviceNameLength)
	if body.Name == "" {
		body.Name = body.Hostname
	}
	if body.Name == "" {
		body.Name = "Unnamed device"
	}

	canon, err := proof.JWK.Canonical()
	if err != nil {
		fail(http.StatusBadRequest, "invalid_request", "unsupported key", "bad jwk")
		return
	}
	inUse, err := s.db.FingerprintInUse(r.Context(), proof.JKT)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "server_error", "could not check key")
		return
	}
	if inUse {
		fail(http.StatusConflict, "key_already_registered", "this key is already registered to a device (revoked keys cannot be re-enrolled)", "fingerprint reuse")
		return
	}

	now := time.Now().UTC()
	status, enrolledAt := model.DeviceStatusActive, now
	if s.settings.Current().RequireDeviceApproval {
		status, enrolledAt = model.DeviceStatusPending, time.Time{}
	}
	dev := &model.Device{
		ID:                 uuid.NewString(),
		OwnerUserID:        user.ID,
		Name:               body.Name,
		Hostname:           body.Hostname,
		Platform:           truncate(strings.ToLower(strings.TrimSpace(body.Platform)), maxDevicePlatformField),
		Architecture:       truncate(strings.ToLower(strings.TrimSpace(body.Architecture)), maxDevicePlatformField),
		PublicKey:          canon,
		PublicKeyAlgorithm: proof.Alg,
		Fingerprint:        proof.JKT,
		Status:             status,
		KeyBackend:         normalizeKeyBackend(body.KeyBackend),
		TrustLevel:         model.TrustForKeyBackend(normalizeKeyBackend(body.KeyBackend)),
		CreatedAt:          now,
		EnrolledAt:         enrolledAt,
	}
	if err := s.db.CreateDevice(r.Context(), dev); err != nil {
		fail(http.StatusConflict, "key_already_registered", "this key is already registered", "create failed")
		return
	}
	s.metrics.recordDeviceEnrollment("success")
	s.audit(r, evtDeviceEnrollCompleted, auditEntry{actorUserID: user.ID, username: user.Username,
		clientID: vt.Audience, success: true, detail: "device=" + dev.ID + " alg=" + dev.PublicKeyAlgorithm + " status=" + dev.Status})
	s.notifyDeviceEnrolled(dev, user)
	writeJSON(w, http.StatusCreated, deviceToJSON(dev, user.Username))
}

// handleDeviceUserLookup answers GET /api/v1/users/lookup?username=… for an
// enrolled device: the NSS bridge on the endpoint needs a user's stable
// subject (to derive a uid) before that user has ever logged in there. Only
// active devices may ask, the answer is the minimum the endpoint needs, and
// unknown or disabled users are indistinguishable (404).
func (s *Server) handleDeviceUserLookup(w http.ResponseWriter, r *http.Request, dev *model.Device) {
	name := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("username")))
	if name == "" || len(name) > 64 {
		apiError(w, http.StatusBadRequest, "invalid_request", "username is required")
		return
	}
	u, err := s.db.GetUserByUsername(r.Context(), name)
	if err != nil || u.Disabled {
		apiError(w, http.StatusNotFound, "not_found", "no such user")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"sub": u.ID, "username": u.Username, "email": u.Email})
}

// requireDevice wraps a device-API handler: the request must carry a valid
// device token for an active device (and a DPoP proof when bound).
func (s *Server) requireDevice(next func(http.ResponseWriter, *http.Request, *model.Device)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		dev, err := s.authenticateDeviceRequest(r)
		if err != nil {
			apiError(w, http.StatusUnauthorized, "invalid_token", err.Error())
			return
		}
		next(w, r, dev)
	}
}

// handleDeviceMe returns the calling device's own record.
func (s *Server) handleDeviceMe(w http.ResponseWriter, r *http.Request, dev *model.Device) {
	owner := ""
	if u, err := s.db.GetUserByID(r.Context(), dev.OwnerUserID); err == nil {
		owner = u.Username
	}
	writeJSON(w, http.StatusOK, deviceToJSON(dev, owner))
}

// handleDeviceRotateKey implements key rotation (docs §8): the request is
// authenticated by the current key (device token + DPoP) and carries a proof
// signed by the NEW key that names the current fingerprint.
func (s *Server) handleDeviceRotateKey(w http.ResponseWriter, r *http.Request, dev *model.Device) {
	var body struct {
		JWK        json.RawMessage `json:"jwk"`
		Proof      string          `json:"proof"`
		KeyBackend string          `json:"key_backend"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDeviceAPIBody)).Decode(&body); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	newKey, err := pop.ParseJWK(body.JWK)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", "invalid jwk: "+err.Error())
		return
	}
	newFP, _ := newKey.Thumbprint()
	newAlg, _ := newKey.Algorithm()
	newPub, _ := newKey.PublicKey()
	var a *pop.Assertion
	for _, aud := range s.serverURLsFor(r) {
		if a, err = pop.VerifyAssertion(body.Proof, pop.AssertionOptions{Key: newPub, Alg: newAlg, Audience: aud}); err == nil {
			break
		}
	}
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid_grant", "new-key proof rejected: "+err.Error())
		return
	}
	if a.Subject != dev.ID {
		apiError(w, http.StatusBadRequest, "invalid_grant", "proof subject must be the device id")
		return
	}
	if oldJKT, _ := a.Claims["old_jkt"].(string); oldJKT != dev.Fingerprint {
		apiError(w, http.StatusBadRequest, "invalid_grant", "proof must name the current key fingerprint in old_jkt")
		return
	}
	fresh, err := s.db.ConsumeJTI(r.Context(), pop.JTIHash(newFP, a.JTI), dev.ID, a.ExpiresAt.Add(pop.DefaultSkew))
	if err != nil || !fresh {
		apiError(w, http.StatusBadRequest, "invalid_grant", "proof replayed")
		return
	}
	if inUse, err := s.db.FingerprintInUse(r.Context(), newFP); err != nil || inUse {
		apiError(w, http.StatusConflict, "key_already_registered", "the new key is already registered")
		return
	}
	canon, _ := newKey.Canonical()
	backend := normalizeKeyBackend(body.KeyBackend)
	trust := dev.TrustLevel
	if backend != "" {
		trust = model.TrustForKeyBackend(backend)
	}
	if err := s.db.RotateDeviceKey(r.Context(), dev.ID, canon, newAlg, newFP, backend, trust); err != nil {
		apiError(w, http.StatusConflict, "invalid_grant", "device is not active")
		return
	}
	detail := "device=" + dev.ID + " alg=" + newAlg
	if backend != "" && trust != dev.TrustLevel {
		detail += " key_backend=" + backend + " trust=" + dev.TrustLevel + "->" + trust
		s.audit(r, evtDeviceTrustChanged, auditEntry{actorUserID: dev.OwnerUserID, success: true, detail: detail})
	}
	s.audit(r, evtDeviceKeyRotated, auditEntry{actorUserID: dev.OwnerUserID, success: true, detail: detail})
	dev.PublicKey, dev.PublicKeyAlgorithm, dev.PreviousFingerprint, dev.Fingerprint = canon, newAlg, dev.Fingerprint, newFP
	if backend != "" {
		dev.KeyBackend, dev.TrustLevel = backend, trust
	}
	writeJSON(w, http.StatusOK, deviceToJSON(dev, ""))
}

// handleDeviceUnenroll lets a device revoke itself.
func (s *Server) handleDeviceUnenroll(w http.ResponseWriter, r *http.Request, dev *model.Device) {
	if err := s.db.RevokeDevice(r.Context(), dev.ID, time.Now().UTC()); err != nil {
		apiError(w, http.StatusConflict, "invalid_grant", "device is not active")
		return
	}
	s.audit(r, evtDeviceRevoked, auditEntry{actorUserID: dev.OwnerUserID, success: true,
		detail: "device=" + dev.ID + " by=device"})
	s.pushRevocation(dev.OwnerUserID, dev.ID, "device unenrolled")
	writeJSON(w, http.StatusOK, map[string]string{"status": model.DeviceStatusRevoked})
}

// --- RFC 7523 §2.1: device assertion → device token ---

// grantJWTBearer authenticates an enrolled device by a JWT signed with its
// registered key and issues a short-lived device token (docs §6).
func (s *Server) grantJWTBearer(w http.ResponseWriter, r *http.Request) {
	client, ok := s.authenticateClient(r)
	if !ok || !client.BuiltIn() {
		oauthClientAuthError(w)
		return
	}
	fail := func(detail string) {
		s.metrics.recordDeviceAuth("failure")
		s.audit(r, evtDeviceAuthFailed, auditEntry{clientID: client.ClientID, detail: detail})
		oauthError(w, http.StatusBadRequest, "invalid_grant", "device assertion rejected")
	}
	raw := r.PostFormValue("assertion")
	deviceID, err := pop.UnverifiedIssuer(raw)
	if err != nil {
		fail("malformed assertion")
		return
	}
	dev, err := s.db.GetDevice(r.Context(), deviceID)
	if err != nil {
		fail("unknown device")
		return
	}
	if dev.IsPending() {
		// Not a refusal of the device's identity: it simply is not approved yet.
		// RFC 8628's authorization_pending is the natural code; the agent keeps
		// polling instead of treating this as a revocation.
		s.audit(r, evtDeviceAuthFailed, auditEntry{clientID: client.ClientID, detail: "device=" + dev.ID + " pending approval"})
		oauthError(w, http.StatusBadRequest, "authorization_pending", "device is pending administrator approval")
		return
	}
	if !dev.IsActive() {
		fail("device=" + dev.ID + " status=" + dev.Status)
		return
	}
	jwk, err := pop.ParseJWK([]byte(dev.PublicKey))
	if err != nil {
		fail("device=" + dev.ID + " stored key unreadable")
		return
	}
	pub, _ := jwk.PublicKey()
	var a *pop.Assertion
	for _, aud := range s.issuerAudiences() {
		if a, err = pop.VerifyAssertion(raw, pop.AssertionOptions{Key: pub, Alg: dev.PublicKeyAlgorithm, Audience: aud}); err == nil {
			break
		}
	}
	if err != nil {
		fail("device=" + dev.ID + " " + err.Error())
		return
	}
	if a.Subject != dev.ID {
		fail("device=" + dev.ID + " sub mismatch")
		return
	}
	fresh, err := s.db.ConsumeJTI(r.Context(), pop.JTIHash(dev.Fingerprint, a.JTI), dev.ID, a.ExpiresAt.Add(pop.DefaultSkew))
	if err != nil || !fresh {
		fail("device=" + dev.ID + " replayed jti")
		return
	}
	owner, err := s.db.GetUserByID(r.Context(), dev.OwnerUserID)
	if err != nil || owner.Disabled {
		fail("device=" + dev.ID + " owner unavailable")
		return
	}

	ttl := s.settings.Current().DeviceTokenTTL
	jkt := dpopJKT(r)
	// audience (optional): a device token for another Omni service, the way
	// token exchange audiences a user token. The audience must be a
	// registered, enabled client, and the token must be DPoP-bound so the
	// service can require proof of possession on every request.
	audience := client.ClientID
	if requested := strings.TrimSpace(r.PostFormValue("audience")); requested != "" && requested != client.ClientID {
		target, err := s.db.GetClient(r.Context(), requested)
		if err != nil || target.Disabled {
			s.metrics.recordDeviceAuth("failure")
			s.audit(r, evtDeviceAuthFailed, auditEntry{clientID: client.ClientID, detail: "device=" + dev.ID + " unknown audience"})
			oauthError(w, http.StatusBadRequest, "invalid_target", "unknown audience")
			return
		}
		if jkt == "" {
			s.metrics.recordDeviceAuth("failure")
			s.audit(r, evtDeviceAuthFailed, auditEntry{clientID: client.ClientID, detail: "device=" + dev.ID + " audience without DPoP"})
			oauthError(w, http.StatusBadRequest, "invalid_dpop_proof", "a device token for another audience requires a DPoP proof")
			return
		}
		audience = target.ClientID
	}
	tok, err := s.issuer.IssueDeviceToken(dev.ID, owner.ID, dev.TrustLevel, audience, jkt, ttl)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not issue device token")
		return
	}
	_ = s.db.TouchDevice(r.Context(), dev.ID, time.Now().UTC())
	s.metrics.recordDeviceAuth("success")
	s.audit(r, evtDeviceAuthSuccess, auditEntry{actorUserID: owner.ID, username: owner.Username,
		clientID: client.ClientID, success: true, detail: "device=" + dev.ID})

	tokenType := "Bearer"
	if jkt != "" {
		tokenType = "DPoP"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok,
		"token_type":   tokenType,
		"expires_in":   int(ttl.Seconds()),
		"token_use":    tokens.TokenUseDevice,
		"device_id":    dev.ID,
		"device_trust": dev.TrustLevel,
	})
}

// --- posture ---

// knownKeyBackends are the values clients may report.
var knownKeyBackends = map[string]bool{model.KeyBackendFile: true, model.KeyBackendDPAPI: true, model.KeyBackendTPM: true, model.KeyBackendSecureEnclave: true, model.KeyBackendStrongBox: true, model.KeyBackendAndroidTEE: true}

func normalizeKeyBackend(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if knownKeyBackends[v] {
		return v
	}
	return ""
}

// parsePosture decodes a stored posture document (nil when empty or bad).
func parsePosture(raw string) *model.DevicePosture {
	if raw == "" {
		return nil
	}
	var p model.DevicePosture
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil
	}
	return &p
}

// handleDevicePosture stores what an enrolled device reports about itself:
// OS, disk encryption, screen lock, key backend. Self-reported and unproven
// (no attestation), which is why it is shown to administrators and offered
// to relying parties as facts the device asserts, never as a verdict. A
// reported key backend also sets the trust level (tpm / secure-enclave →
// hardware) so that a client whose key moved is not stuck at "enrolled".
func (s *Server) handleDevicePosture(w http.ResponseWriter, r *http.Request, dev *model.Device) {
	var in model.DevicePosture
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	in.OSName = truncate(strings.TrimSpace(in.OSName), 64)
	in.OSVersion = truncate(strings.TrimSpace(in.OSVersion), 64)
	in.KeyBackend = normalizeKeyBackend(in.KeyBackend)
	raw, err := json.Marshal(in)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", "bad posture")
		return
	}
	now := time.Now().UTC()
	trust := dev.TrustLevel
	if in.KeyBackend != "" {
		trust = model.TrustForKeyBackend(in.KeyBackend)
	}
	if err := s.db.SetDevicePosture(r.Context(), dev.ID, string(raw), now, in.KeyBackend, trust); err != nil {
		apiError(w, http.StatusInternalServerError, "server_error", "could not store posture")
		return
	}
	if trust != dev.TrustLevel {
		s.audit(r, evtDeviceTrustChanged, auditEntry{actorUserID: dev.OwnerUserID, success: true,
			detail: "device=" + dev.ID + " key_backend=" + in.KeyBackend + " trust " + dev.TrustLevel + " -> " + trust})
	}
	writeJSON(w, http.StatusOK, map[string]any{"trust_level": trust, "posture_at": now.Format(time.RFC3339)})
}
