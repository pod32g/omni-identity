package web

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/oidc"
	"github.com/pod32g/omni-identity/internal/pop"
	"github.com/pod32g/omni-identity/internal/tokens"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// tokenContext carries the optional bindings applied to a token response:
// how the user authenticated (amr), the enrolled device the grant was
// authenticated by, and the DPoP key thumbprint to bind the tokens to.
type tokenContext struct {
	amr    string
	device *model.Device
	jkt    string
}

// extra renders the context as additional JWT claims (empty when unbound).
func (tc tokenContext) extra() tokens.Extra {
	e := tokens.Extra{}
	if tc.amr != "" {
		e["amr"] = tokens.AMRList(tc.amr)
	}
	if tc.device != nil {
		e["device_id"] = tc.device.ID
		e["device_trust"] = tc.device.TrustLevel
	}
	if tc.jkt != "" {
		e["cnf"] = map[string]any{"jkt": tc.jkt}
	}
	if len(e) == 0 {
		return nil
	}
	return e
}

func (tc tokenContext) deviceID() string {
	if tc.device == nil {
		return ""
	}
	return tc.device.ID
}

func (tc tokenContext) tokenType() string {
	if tc.jkt != "" {
		return "DPoP"
	}
	return "Bearer"
}

// dpopCtxKey carries the validated DPoP proof of a token request.
type dpopCtxKey struct{}

// handleToken implements the OAuth2 token endpoint (authorization_code,
// refresh_token, client_credentials, RFC 8628 device_code, RFC 7523 jwt-bearer).
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}

	// An optional DPoP proof (RFC 9449 §5) sender-constrains the tokens issued
	// by any grant. An invalid proof is an error; no proof is plain bearer.
	if raw := r.Header.Get("DPoP"); raw != "" {
		proof, err := s.verifyDPoP(r, raw, "")
		if err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_dpop_proof", err.Error())
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), dpopCtxKey{}, proof))
	}

	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		s.grantAuthorizationCode(w, r)
	case "refresh_token":
		s.grantRefreshToken(w, r)
	case "client_credentials":
		s.grantClientCredentials(w, r)
	case oidc.GrantTypeDeviceCode:
		s.grantDeviceCode(w, r)
	case oidc.GrantTypeJWTBearer:
		s.grantJWTBearer(w, r)
	case oidc.GrantTypeTokenExchange:
		s.grantTokenExchange(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

// dpopJKT returns the thumbprint of the DPoP key that proved possession on
// this token request, or "" when no proof was presented.
func dpopJKT(r *http.Request) string {
	if p, ok := r.Context().Value(dpopCtxKey{}).(*pop.Proof); ok && p != nil {
		return p.JKT
	}
	return ""
}

// verifyDPoP validates a DPoP proof against this request (method + public URL
// path, optional access-token hash) and consumes its jti so it cannot be
// replayed. Returns the proof on success.
func (s *Server) verifyDPoP(r *http.Request, raw, accessToken string) (*pop.Proof, error) {
	proof, err := pop.VerifyProof(raw, pop.ProofOptions{
		HTM:         r.Method,
		HTU:         s.publicURLFor(r),
		AccessToken: accessToken,
	})
	if err != nil {
		return nil, err
	}
	fresh, err := s.db.ConsumeJTI(r.Context(), pop.JTIHash(proof.JKT, proof.JTI), "",
		proof.IssuedAt.Add(2*pop.DefaultSkew))
	if err != nil {
		return nil, err
	}
	if !fresh {
		return nil, errDPoPReplay
	}
	return proof, nil
}

// publicURLFor is the absolute URL of this request as clients see it (the live
// public URL + path), the value a DPoP htu must match.
func (s *Server) publicURLFor(r *http.Request) string {
	return strings.TrimRight(s.settings.Current().PublicURL, "/") + r.URL.Path
}

func (s *Server) grantAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	client, ok := s.authenticateClient(r)
	if !ok {
		oauthClientAuthError(w)
		return
	}

	rawCode := r.PostFormValue("code")
	if rawCode == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "missing code")
		return
	}

	code, err := s.db.ConsumeAuthCode(r.Context(), auth.HashToken(rawCode))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")
		return
	}
	if code.ClientID != client.ClientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code was issued to a different client")
		return
	}
	if code.RedirectURI != r.PostFormValue("redirect_uri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	// PKCE verification.
	verifier := r.PostFormValue("code_verifier")
	if code.CodeChallenge != "" {
		if verifier == "" || !oidc.VerifyPKCE(verifier, code.CodeChallenge, code.CodeChallengeMethod) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	} else if client.IsPublic() {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE is required")
		return
	}

	user, err := s.db.GetUserByID(r.Context(), code.UserID)
	if err != nil || user.Disabled {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "user is not available")
		return
	}

	tc := tokenContext{amr: code.AMR, jkt: dpopJKT(r)}
	resp, err := s.buildAccessAndID(client, user, code.Scope, code.Nonce, code.AuthTime, tc)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not issue tokens")
		return
	}
	if oidc.HasScope(code.Scope, oidc.ScopeOfflineAccess) {
		raw, newRT := s.newRefreshToken(client, user, code.Scope, code.AuthTime, "", tc)
		if err := s.db.CreateRefreshToken(r.Context(), newRT); err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", "could not issue refresh token")
			return
		}
		resp.RefreshToken = raw
	}
	s.recordTokenMetrics(resp)
	s.audit(r, evtTokenIssued, auditEntry{actorUserID: user.ID, username: user.Username, clientID: client.ClientID, success: true, detail: "authorization_code"})
	writeJSON(w, http.StatusOK, resp)
}

// recordTokenMetrics counts the tokens present in a successful token response.
func (s *Server) recordTokenMetrics(resp tokenResponse) {
	if resp.AccessToken != "" {
		s.metrics.recordToken("access")
	}
	if resp.IDToken != "" {
		s.metrics.recordToken("id")
	}
	if resp.RefreshToken != "" {
		s.metrics.recordToken("refresh")
	}
}

func (s *Server) grantRefreshToken(w http.ResponseWriter, r *http.Request) {
	client, ok := s.authenticateClient(r)
	if !ok {
		oauthClientAuthError(w)
		return
	}

	raw := r.PostFormValue("refresh_token")
	if raw == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "missing refresh_token")
		return
	}

	rt, err := s.db.GetRefreshTokenByHash(r.Context(), auth.HashToken(raw))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		return
	}
	if rt.ClientID != client.ClientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token client mismatch")
		return
	}
	if rt.Revoked {
		// Reuse of an already-rotated token: revoke the whole chain.
		_ = s.db.RevokeRefreshTokensForUserClient(r.Context(), rt.UserID, rt.ClientID)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected")
		return
	}
	if time.Now().After(rt.ExpiresAt) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}
	// A DPoP-bound refresh token (RFC 9449 §5) must be presented with a proof
	// from the same key; a plain copy of the token is useless.
	jkt := dpopJKT(r)
	if rt.DPoPJKT != "" && jkt != rt.DPoPJKT {
		oauthError(w, http.StatusBadRequest, "invalid_dpop_proof", "refresh token is bound to a different DPoP key")
		return
	}

	user, err := s.db.GetUserByID(r.Context(), rt.UserID)
	if err != nil || user.Disabled {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "user is not available")
		return
	}

	// A device-bound refresh token only refreshes while the device is active.
	tc := tokenContext{amr: rt.AMR, jkt: jkt}
	if rt.DeviceID != "" {
		dev, err := s.db.GetDevice(r.Context(), rt.DeviceID)
		if err != nil || !dev.IsActive() {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "device is not active")
			return
		}
		tc.device = dev
	}

	// Optional down-scoping; new scope must be a subset of the original grant.
	scope := rt.Scope
	if requested := r.PostFormValue("scope"); requested != "" {
		if !oidc.ScopesSubset(oidc.SplitScope(requested), oidc.SplitScope(rt.Scope)) {
			oauthError(w, http.StatusBadRequest, "invalid_scope", "scope exceeds the original grant")
			return
		}
		scope = requested
	}

	// Sign access + ID tokens first; signing can fail without consuming the
	// presented refresh token.
	resp, err := s.buildAccessAndID(client, user, scope, "", rt.AuthTime, tc)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not issue tokens")
		return
	}

	// Build the replacement refresh token (preserving the original auth_time).
	var rawRefresh string
	var newRT *model.RefreshToken
	if oidc.HasScope(scope, oidc.ScopeOfflineAccess) {
		rawRefresh, newRT = s.newRefreshToken(client, user, scope, rt.AuthTime, rt.ID, tc)
	}

	// Atomically revoke the presented token and persist the replacement. ok=false
	// means another request already rotated it: treat as reuse and revoke the chain.
	ok, err = s.db.RotateRefreshToken(r.Context(), rt.ID, newRT)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not rotate refresh token")
		return
	}
	if !ok {
		_ = s.db.RevokeRefreshTokensForUserClient(r.Context(), rt.UserID, rt.ClientID)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected")
		return
	}

	if newRT != nil {
		resp.RefreshToken = rawRefresh
	}
	s.recordTokenMetrics(resp)
	s.audit(r, evtTokenIssued, auditEntry{actorUserID: user.ID, username: user.Username, clientID: client.ClientID, success: true, detail: "refresh_token"})
	writeJSON(w, http.StatusOK, resp)
}

// buildAccessAndID signs an access token and, when openid is granted, an ID
// token carrying the supplied authentication time plus any bindings in tc.
func (s *Server) buildAccessAndID(client *model.Client, user *model.User, scope, nonce string, authTime time.Time, tc tokenContext) (tokenResponse, error) {
	extra := withGroups(tc.extra(), user)
	access, err := s.issuer.IssueAccessTokenWithClaims(user.ID, client.ClientID, scope, extra)
	if err != nil {
		return tokenResponse{}, err
	}
	resp := tokenResponse{
		AccessToken: access,
		TokenType:   tc.tokenType(),
		ExpiresIn:   int(s.issuer.AccessTTL().Seconds()),
		Scope:       scope,
	}
	if oidc.HasScope(scope, oidc.ScopeOpenID) {
		// The ID token identifies the user; cnf belongs on the access token only.
		idExtra := tokens.Extra{}
		for k, v := range extra {
			if k != "cnf" {
				idExtra[k] = v
			}
		}
		idTok, err := s.issuer.IssueIDTokenWithClaims(user.ID, client.ClientID, profileFromUser(user), nonce, authTime, idExtra)
		if err != nil {
			return tokenResponse{}, err
		}
		resp.IDToken = idTok
	}
	return resp, nil
}

// newRefreshToken builds (but does not persist) a refresh token record and
// returns the plaintext value to hand to the client.
func (s *Server) newRefreshToken(client *model.Client, user *model.User, scope string, authTime time.Time, rotatedFrom string, tc tokenContext) (string, *model.RefreshToken) {
	raw := auth.RandomToken(24)
	now := time.Now().UTC()
	return raw, &model.RefreshToken{
		ID:          uuid.NewString(),
		TokenHash:   auth.HashToken(raw),
		ClientID:    client.ClientID,
		UserID:      user.ID,
		Scope:       scope,
		RotatedFrom: rotatedFrom,
		ExpiresAt:   now.Add(s.settings.Current().RefreshTokenTTL),
		CreatedAt:   now,
		AuthTime:    authTime,
		AMR:         tc.amr,
		DeviceID:    tc.deviceID(),
		DPoPJKT:     tc.jkt,
	}
}

// authenticateClient resolves and authenticates the client from Basic auth or
// POST body credentials.
func (s *Server) authenticateClient(r *http.Request) (*model.Client, bool) {
	clientID, secret, hasBasic := r.BasicAuth()
	if !hasBasic {
		clientID = r.PostFormValue("client_id")
		secret = r.PostFormValue("client_secret")
	}
	if clientID == "" {
		return nil, false
	}
	client, err := s.db.GetClient(r.Context(), clientID)
	if err != nil || client.Disabled {
		return nil, false
	}
	if client.Type == model.ClientTypeConfidential {
		if secret == "" || !auth.SecretMatches(secret, client.ClientSecretHash) {
			return nil, false
		}
	}
	return client, true
}

// userGroups renders the user's memberships as the groups claim. Omni has no
// group model; the only membership is the administrator flag, so V1 yields
// ["admins"] for administrators and nil (claim absent) for everyone else.
func userGroups(u *model.User) []string {
	if u != nil && u.IsAdmin {
		return []string{"admins"}
	}
	return nil
}

// withGroups returns extra plus the groups claim when the user has any. It
// never mutates extra (which may be nil).
func withGroups(extra tokens.Extra, u *model.User) tokens.Extra {
	groups := userGroups(u)
	if len(groups) == 0 {
		return extra
	}
	out := tokens.Extra{}
	for k, v := range extra {
		out[k] = v
	}
	out["groups"] = groups
	return out
}

// profileFromUser maps a user to ID-token identity claims. Admin-provisioned
// emails are treated as verified in V1.
func profileFromUser(u *model.User) tokens.Profile {
	return tokens.Profile{
		Email:             u.Email,
		EmailVerified:     true,
		PreferredUsername: u.Username,
		Name:              u.Username,
	}
}
