package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/oidc"
	"github.com/pod32g/omni-identity/internal/tokens"
)

// Personal access tokens (docs/BEARER.md): a signed-in user creates a
// long-lived, device-bound bearer token from an enrolled client for scripts
// and curl, and lists/revokes them from the same client. Authentication is the
// device token (like the other /api/v1/devices/me endpoints); creation also
// takes the user's device-bound refresh token in the body to prove the user
// session, exactly as the RFC 8693 exchange does.

const (
	patDefaultTTL = 90 * 24 * time.Hour
	patMaxTTL     = 365 * 24 * time.Hour
	patMinTTL     = time.Hour
)

type createPATRequest struct {
	Name         string `json:"name"`
	Audience     string `json:"audience"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"` // seconds; 0 = default
	RefreshToken string `json:"refresh_token"`
}

type patJSON struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Audience   string `json:"audience"`
	Scope      string `json:"scope"`
	CreatedAt  string `json:"created_at"`
	ExpiresAt  string `json:"expires_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	Token      string `json:"token,omitempty"` // only on creation
}

func (s *Server) handleCreatePAT(w http.ResponseWriter, r *http.Request, dev *model.Device) {
	var body createPATRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	audience := strings.TrimSpace(body.Audience)
	if audience == "" {
		apiError(w, http.StatusBadRequest, "invalid_request", "audience is required")
		return
	}
	name := truncate(strings.TrimSpace(body.Name), 100)

	// Prove the user session: a refresh token bound to this device and its key.
	if body.RefreshToken == "" {
		apiError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required to prove the signed-in user")
		return
	}
	rt, err := s.db.GetRefreshTokenByHash(r.Context(), auth.HashToken(body.RefreshToken))
	if err != nil || rt.Revoked || time.Now().After(rt.ExpiresAt) {
		apiError(w, http.StatusUnauthorized, "invalid_grant", "refresh_token is not valid")
		return
	}
	if rt.DeviceID != dev.ID || rt.DPoPJKT != dev.Fingerprint {
		apiError(w, http.StatusUnauthorized, "invalid_grant", "refresh_token is not bound to this device")
		return
	}
	user, err := s.db.GetUserByID(r.Context(), rt.UserID)
	if err != nil || user.Disabled {
		apiError(w, http.StatusUnauthorized, "invalid_grant", "user is not available")
		return
	}

	// Audience: a registered, enabled client; scope ⊆ the grant ∩ its allowed scopes.
	target, err := s.db.GetClient(r.Context(), audience)
	if err != nil || target.Disabled {
		apiError(w, http.StatusBadRequest, "invalid_target", "unknown audience")
		return
	}
	scope := strings.TrimSpace(body.Scope)
	if scope == "" {
		scope = strings.Join(intersectScopes(oidc.SplitScope(rt.Scope), target.AllowedScopes), " ")
	}
	requested := oidc.SplitScope(scope)
	if len(requested) == 0 || !oidc.ScopesSubset(requested, oidc.SplitScope(rt.Scope)) || !oidc.ScopesSubset(requested, target.AllowedScopes) {
		apiError(w, http.StatusBadRequest, "invalid_scope", "scope must be within the user's grant and the audience's allowed scopes")
		return
	}

	ttl := patDefaultTTL
	if body.ExpiresIn > 0 {
		ttl = time.Duration(body.ExpiresIn) * time.Second
	}
	if ttl < patMinTTL {
		ttl = patMinTTL
	}
	if ttl > patMaxTTL {
		ttl = patMaxTTL
	}

	// The same device-delegation claims the exchange emits, so the gateway
	// treats the token identically (X-Omni-* headers, device policy).
	extra := tokens.Extra{
		"device_id":    dev.ID,
		"device_trust": dev.TrustLevel,
		"act":          map[string]any{"sub": dev.ID},
	}
	if rt.AMR != "" {
		extra["amr"] = tokens.AMRList(rt.AMR)
	}
	if !rt.AuthTime.IsZero() {
		extra["auth_time"] = rt.AuthTime.Unix()
	}
	extra = withGroups(extra, user)
	if p := parsePosture(dev.Posture); p != nil {
		extra["device_posture"] = p
	}
	if oidc.HasScope(scope, oidc.ScopeProfile) {
		extra["preferred_username"] = user.Username
	}
	if oidc.HasScope(scope, oidc.ScopeEmail) && user.Email != "" {
		extra["email"] = user.Email
	}

	jti := uuid.NewString()
	token, err := s.issuer.IssuePersonalAccessToken(user.ID, target.ClientID, scope, jti, ttl, extra)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		return
	}
	now := time.Now().UTC()
	pat := &model.PersonalAccessToken{
		ID: jti, UserID: user.ID, DeviceID: dev.ID, ClientID: target.ClientID,
		Name: name, Scope: scope, CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	if err := s.db.CreatePAT(r.Context(), pat); err != nil {
		apiError(w, http.StatusInternalServerError, "server_error", "could not record token")
		return
	}
	s.metrics.recordToken("access")
	s.audit(r, evtTokenIssued, auditEntry{actorUserID: user.ID, username: user.Username, clientID: target.ClientID,
		success: true, detail: "personal_access_token device=" + dev.ID + " jti=" + jti})
	writeJSON(w, http.StatusOK, patView(pat, token))
}

func (s *Server) handleListPATs(w http.ResponseWriter, r *http.Request, dev *model.Device) {
	list, err := s.db.ListActivePATsForDevice(r.Context(), dev.ID)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "server_error", "could not list tokens")
		return
	}
	out := make([]patJSON, 0, len(list))
	for i := range list {
		out = append(out, patView(&list[i], ""))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

func (s *Server) handleRevokePAT(w http.ResponseWriter, r *http.Request, dev *model.Device) {
	id := r.PathValue("id")
	ok, err := s.db.RevokePATForDevice(r.Context(), id, dev.ID)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "server_error", "could not revoke token")
		return
	}
	if !ok {
		apiError(w, http.StatusNotFound, "not_found", "no such active token on this device")
		return
	}
	s.audit(r, evtTokenRevoked, auditEntry{actorUserID: dev.OwnerUserID, clientID: "", success: true,
		detail: "personal_access_token device=" + dev.ID + " jti=" + id})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": id})
}

// handleRevokedTokens lists the ids of revoked, not-yet-expired personal
// access tokens so a resource server (the Omni Access gateway) can reject
// them. The ids are opaque and belong to dead tokens; the list is public.
func (s *Server) handleRevokedTokens(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	jtis, err := s.db.RevokedPATJTIs(r.Context())
	if err != nil {
		apiError(w, http.StatusInternalServerError, "server_error", "could not list revoked tokens")
		return
	}
	if jtis == nil {
		jtis = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"jtis": jtis, "as_of": time.Now().UTC().Format(time.RFC3339)})
}

func patView(p *model.PersonalAccessToken, token string) patJSON {
	v := patJSON{
		ID: p.ID, Name: p.Name, Audience: p.ClientID, Scope: p.Scope,
		CreatedAt: p.CreatedAt.UTC().Format(time.RFC3339),
		ExpiresAt: p.ExpiresAt.UTC().Format(time.RFC3339),
		Token:     token,
	}
	if p.LastUsedAt != nil {
		v.LastUsedAt = p.LastUsedAt.UTC().Format(time.RFC3339)
	}
	return v
}
