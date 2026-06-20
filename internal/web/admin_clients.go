package web

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/oidc"
)

// httpsOrLocalURLs reports whether every entry is an absolute http(s) URL with a
// host and no wildcard — the shape required for exact redirect matching.
func httpsOrLocalURLs(uris []string) bool {
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || strings.Contains(raw, "*") {
			return false
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return false
		}
	}
	return true
}

type adminClientsPage struct {
	CSRFToken string
	Me        *model.User
	Active    string
	Clients   []model.Client
	Error     string
}

type adminClientDetailPage struct {
	CSRFToken          string
	Me                 *model.User
	Active             string
	Client             *model.Client
	RedirectURIsText   string
	ScopesText         string
	PostLogoutURIsText string
	SupportedScopes    []string
	NewSecret          string // shown once, after create/rotate
	Error              string
}

func (s *Server) renderClients(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	clients, _ := s.db.ListClients(r.Context())
	s.tmpl.render(w, status, "admin_clients", adminClientsPage{
		CSRFToken: auth.CSRFToken(w, r, s.cfg.Cookies.Secure),
		Me:        currentUser(r),
		Active:    "clients",
		Clients:   clients,
		Error:     errMsg,
	})
}

func (s *Server) renderClientDetail(w http.ResponseWriter, r *http.Request, status int, c *model.Client, newSecret, errMsg string) {
	s.tmpl.render(w, status, "admin_client_detail", adminClientDetailPage{
		CSRFToken:          auth.CSRFToken(w, r, s.cfg.Cookies.Secure),
		Me:                 currentUser(r),
		Active:             "clients",
		Client:             c,
		RedirectURIsText:   strings.Join(c.RedirectURIs, "\n"),
		ScopesText:         strings.Join(c.AllowedScopes, " "),
		PostLogoutURIsText: strings.Join(c.PostLogoutRedirectURIs, "\n"),
		SupportedScopes:    oidc.SupportedScopes,
		NewSecret:          newSecret,
		Error:              errMsg,
	})
}

func (s *Server) handleAdminClients(w http.ResponseWriter, r *http.Request) {
	s.renderClients(w, r, http.StatusOK, "")
}

func (s *Server) handleAdminClientDetail(w http.ResponseWriter, r *http.Request) {
	c, err := s.db.GetClient(r.Context(), r.PathValue("id"))
	if err != nil {
		s.renderError(w, http.StatusNotFound, "Client not found.")
		return
	}
	s.renderClientDetail(w, r, http.StatusOK, c, "", "")
}

type clientForm struct {
	clientID       string
	name           string
	clientType     string
	redirectURIs   []string
	scopes         []string
	displayName    string
	logoURL        string
	homepageURL    string
	postLogoutURIs []string
	skipConsent    bool
}

func parseClientForm(r *http.Request) (clientForm, string) {
	f := clientForm{
		clientID:       strings.TrimSpace(r.PostFormValue("client_id")),
		name:           strings.TrimSpace(r.PostFormValue("name")),
		clientType:     r.PostFormValue("type"),
		redirectURIs:   strings.Fields(r.PostFormValue("redirect_uris")),
		scopes:         strings.Fields(r.PostFormValue("scopes")),
		displayName:    strings.TrimSpace(r.PostFormValue("display_name")),
		logoURL:        strings.TrimSpace(r.PostFormValue("logo_url")),
		homepageURL:    strings.TrimSpace(r.PostFormValue("homepage_url")),
		postLogoutURIs: strings.Fields(r.PostFormValue("post_logout_redirect_uris")),
		skipConsent:    r.PostFormValue("skip_consent") == "on" || r.PostFormValue("skip_consent") == "true",
	}
	if f.name == "" {
		return f, "Name is required."
	}
	if f.clientType != model.ClientTypePublic && f.clientType != model.ClientTypeConfidential {
		return f, "Type must be public or confidential."
	}
	if len(f.redirectURIs) == 0 {
		return f, "At least one redirect URI is required."
	}
	if len(f.scopes) == 0 {
		return f, "At least one scope is required."
	}
	if !oidc.ScopesSubset(f.scopes, oidc.SupportedScopes) {
		return f, "Unknown scope requested."
	}
	if !httpsOrLocalURLs(f.redirectURIs) {
		return f, "Redirect URIs must be absolute http(s) URLs."
	}
	if !httpsOrLocalURLs(f.postLogoutURIs) {
		return f, "Post-logout redirect URIs must be absolute http(s) URLs."
	}
	return f, ""
}

func (s *Server) handleAdminCreateClient(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	form, errMsg := parseClientForm(r)
	if errMsg != "" {
		s.renderClients(w, r, http.StatusBadRequest, errMsg)
		return
	}

	clientID := form.clientID
	if clientID == "" {
		clientID = "omni_" + auth.RandomToken(6)
	}
	if _, err := s.db.GetClient(r.Context(), clientID); err == nil {
		s.renderClients(w, r, http.StatusBadRequest, "A client with that client_id already exists.")
		return
	}

	var secret, secretHash string
	if form.clientType == model.ClientTypeConfidential {
		secret = auth.RandomToken(24)
		secretHash = auth.HashToken(secret)
	}

	now := time.Now().UTC()
	c := &model.Client{
		ClientID:               clientID,
		ClientSecretHash:       secretHash,
		Name:                   form.name,
		RedirectURIs:           form.redirectURIs,
		AllowedScopes:          form.scopes,
		Type:                   form.clientType,
		DisplayName:            form.displayName,
		LogoURL:                form.logoURL,
		HomepageURL:            form.homepageURL,
		PostLogoutRedirectURIs: form.postLogoutURIs,
		SkipConsent:            form.skipConsent,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if err := s.db.CreateClient(r.Context(), c); err != nil {
		s.renderClients(w, r, http.StatusBadRequest, "Could not create client.")
		return
	}
	// Show the secret exactly once.
	s.renderClientDetail(w, r, http.StatusOK, c, secret, "")
}

func (s *Server) handleAdminUpdateClient(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	existing, err := s.db.GetClient(r.Context(), r.PathValue("id"))
	if err != nil {
		s.renderError(w, http.StatusNotFound, "Client not found.")
		return
	}
	form, errMsg := parseClientForm(r)
	if errMsg != "" {
		s.renderClientDetail(w, r, http.StatusBadRequest, existing, "", errMsg)
		return
	}
	existing.Name = form.name
	existing.Type = form.clientType
	existing.RedirectURIs = form.redirectURIs
	existing.AllowedScopes = form.scopes
	existing.DisplayName = form.displayName
	existing.LogoURL = form.logoURL
	existing.HomepageURL = form.homepageURL
	existing.PostLogoutRedirectURIs = form.postLogoutURIs
	existing.SkipConsent = form.skipConsent
	if err := s.db.UpdateClient(r.Context(), existing); err != nil {
		s.renderClientDetail(w, r, http.StatusBadRequest, existing, "", "Could not update client.")
		return
	}
	http.Redirect(w, r, "/admin/clients/"+existing.ClientID, http.StatusSeeOther)
}

func (s *Server) handleAdminToggleClient(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	disabled := r.PostFormValue("disabled") == "true"
	if err := s.db.SetClientDisabled(r.Context(), r.PathValue("id"), disabled); err != nil {
		s.renderClients(w, r, http.StatusBadRequest, "Could not update client.")
		return
	}
	http.Redirect(w, r, "/admin/clients", http.StatusSeeOther)
}

func (s *Server) handleAdminRotateClient(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	c, err := s.db.GetClient(r.Context(), r.PathValue("id"))
	if err != nil {
		s.renderError(w, http.StatusNotFound, "Client not found.")
		return
	}
	if c.Type != model.ClientTypeConfidential {
		s.renderClientDetail(w, r, http.StatusBadRequest, c, "", "Public clients do not have a secret to rotate.")
		return
	}
	secret := auth.RandomToken(24)
	if err := s.db.SetClientSecretHash(r.Context(), c.ClientID, auth.HashToken(secret)); err != nil {
		s.renderClientDetail(w, r, http.StatusBadRequest, c, "", "Could not rotate secret.")
		return
	}
	c.ClientSecretHash = auth.HashToken(secret)
	s.renderClientDetail(w, r, http.StatusOK, c, secret, "")
}
