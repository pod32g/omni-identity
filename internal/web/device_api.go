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
	OwnerSub     string `json:"owner_sub"`
	OwnerName    string `json:"owner_username,omitempty"`
	EnrolledAt   string `json:"enrolled_at,omitempty"`
	LastSeenAt   string `json:"last_seen_at,omitempty"`
	RevokedAt    string `json:"revoked_at,omitempty"`
}

func deviceToJSON(d *model.Device, ownerName string) deviceJSON {
	j := deviceJSON{
		ID: d.ID, Name: d.Name, Hostname: d.Hostname, Platform: d.Platform, Architecture: d.Architecture,
		Fingerprint: d.Fingerprint, Algorithm: d.PublicKeyAlgorithm, Status: d.Status, TrustLevel: d.TrustLevel,
		OwnerSub: d.OwnerUserID, OwnerName: ownerName,
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
		Status:             model.DeviceStatusActive,
		TrustLevel:         model.DeviceTrustEnrolled,
		CreatedAt:          now,
		EnrolledAt:         now,
	}
	if err := s.db.CreateDevice(r.Context(), dev); err != nil {
		fail(http.StatusConflict, "key_already_registered", "this key is already registered", "create failed")
		return
	}
	s.metrics.recordDeviceEnrollment("success")
	s.audit(r, evtDeviceEnrollCompleted, auditEntry{actorUserID: user.ID, username: user.Username,
		clientID: vt.Audience, success: true, detail: "device=" + dev.ID + " alg=" + dev.PublicKeyAlgorithm})
	writeJSON(w, http.StatusCreated, deviceToJSON(dev, user.Username))
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
		JWK   json.RawMessage `json:"jwk"`
		Proof string          `json:"proof"`
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
	a, err := pop.VerifyAssertion(body.Proof, pop.AssertionOptions{
		Key: newPub, Alg: newAlg, Audience: s.publicURLFor(r),
	})
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
	if err := s.db.RotateDeviceKey(r.Context(), dev.ID, canon, newAlg, newFP); err != nil {
		apiError(w, http.StatusConflict, "invalid_grant", "device is not active")
		return
	}
	s.audit(r, evtDeviceKeyRotated, auditEntry{actorUserID: dev.OwnerUserID, success: true,
		detail: "device=" + dev.ID + " alg=" + newAlg})
	dev.PublicKey, dev.PublicKeyAlgorithm, dev.PreviousFingerprint, dev.Fingerprint = canon, newAlg, dev.Fingerprint, newFP
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
	a, err := pop.VerifyAssertion(raw, pop.AssertionOptions{
		Key: pub, Alg: dev.PublicKeyAlgorithm, Audience: s.settings.Current().Issuer,
	})
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
	tok, err := s.issuer.IssueDeviceToken(dev.ID, owner.ID, dev.TrustLevel, client.ClientID, jkt, ttl)
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
