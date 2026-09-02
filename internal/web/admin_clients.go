package web

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/oidc"
)

// httpsOrLocalURLs reports whether every entry is an absolute URL suitable for
// OAuth redirects: https in production, with http allowed only for loopback
// native/local development clients. When allowPrivateNetworkHTTP is true
// (homelab / private LAN deployments), http is also accepted for hosts that
// cannot be reached from the public Internet — see isPrivateNetworkHost. When
// allowPrivateScheme is true (native public clients), reverse-DNS private-use
// URI scheme redirects are also permitted per RFC 8252 §7.1 (e.g.
// com.example.app://oauth/callback) — these let mobile apps receive the
// redirect without a hosted https domain.
func httpsOrLocalURLs(uris []string, allowLoopbackHTTP, allowPrivateNetworkHTTP, allowPrivateScheme bool) bool {
	for _, raw := range uris {
		if strings.Contains(raw, "*") {
			return false
		}
		u, err := url.Parse(raw)
		if err != nil {
			return false
		}
		if u.User != nil || u.Fragment != "" {
			return false
		}
		switch u.Scheme {
		case "https":
			if u.Host == "" {
				return false
			}
			continue
		case "http":
			if u.Host != "" && allowLoopbackHTTP && isLoopbackHost(u.Hostname()) {
				continue
			}
			if u.Host != "" && allowPrivateNetworkHTTP && isPrivateNetworkHost(u.Hostname()) {
				continue
			}
		default:
			if allowPrivateScheme && isPrivateUseScheme(u.Scheme) {
				continue
			}
		}
		return false
	}
	return true
}

// privateNetworkSuffixes are DNS suffixes that are reserved or withheld from
// the public DNS root, so a name under them can only resolve on a local
// network: home.arpa (RFC 8375), internal (ICANN private-use, 2024), local
// (mDNS, RFC 6762), localdomain, and the conventional lan/home/corp (ICANN
// permanently withholds home and corp because of name-collision risk).
var privateNetworkSuffixes = []string{".home.arpa", ".internal", ".local", ".localdomain", ".lan", ".home", ".corp"}

// isPrivateNetworkHost reports whether host is only reachable inside a
// private network, which is the homelab justification for accepting an http
// redirect URI: the authorization code never crosses the public Internet.
//
// Accepted: RFC 1918 / ULA addresses, link-local addresses, the CGNAT range
// 100.64.0.0/10 (used by Tailscale and similar overlays), single-label
// hostnames (unqualified names never resolve publicly), and hostnames under
// privateNetworkSuffixes. Loopback is handled by the separate loopback policy.
// Everything else — public IPs, and any ordinary domain name — is not.
func isPrivateNetworkHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false // loopback names belong to the loopback policy
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			return false
		}
		if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return true
		}
		if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1]&0xc0 == 64 {
			return true // 100.64.0.0/10, RFC 6598 shared address space
		}
		return false
	}
	if !strings.Contains(host, ".") {
		return true
	}
	for _, suffix := range privateNetworkSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// isPrivateUseScheme reports whether scheme is a reverse-DNS private-use URI
// scheme (RFC 8252 §7.1): contains a dot and is not http(s). Using a reverse-DNS
// name (e.g. com.omnivideo.app) makes collisions between native apps unlikely.
func isPrivateUseScheme(scheme string) bool {
	s := strings.ToLower(scheme)
	if s == "" || s == "http" || s == "https" {
		return false
	}
	return strings.Contains(s, ".")
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
		CSRFToken: auth.CSRFToken(w, r, s.cookieSecure()),
		Me:        currentUser(r),
		Active:    "clients",
		Clients:   clients,
		Error:     errMsg,
	})
}

func (s *Server) renderClientDetail(w http.ResponseWriter, r *http.Request, status int, c *model.Client, newSecret, errMsg string) {
	s.tmpl.render(w, status, "admin_client_detail", adminClientDetailPage{
		CSRFToken:          auth.CSRFToken(w, r, s.cookieSecure()),
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

func parseClientForm(r *http.Request, allowLoopbackHTTP, allowPrivateNetworkHTTP, allowPrivateSchemeSetting bool) (clientForm, string) {
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
	// Native (public) clients may use a private-use URI scheme redirect so the
	// app can receive the callback without a hosted https domain — when the
	// admin setting allows it.
	allowPrivateScheme := allowPrivateSchemeSetting && f.clientType == model.ClientTypePublic
	if !httpsOrLocalURLs(f.redirectURIs, allowLoopbackHTTP, allowPrivateNetworkHTTP, allowPrivateScheme) {
		return f, redirectURIMessage("Redirect", allowLoopbackHTTP, allowPrivateNetworkHTTP, allowPrivateScheme)
	}
	if !httpsOrLocalURLs(f.postLogoutURIs, allowLoopbackHTTP, allowPrivateNetworkHTTP, allowPrivateScheme) {
		return f, redirectURIMessage("Post-logout redirect", allowLoopbackHTTP, allowPrivateNetworkHTTP, allowPrivateScheme)
	}
	return f, ""
}

func redirectURIMessage(kind string, allowLoopbackHTTP, allowPrivateNetworkHTTP, allowPrivateScheme bool) string {
	msg := kind + " URIs must use HTTPS"
	if allowLoopbackHTTP {
		msg += ", or http://localhost / loopback addresses for local development"
	}
	if allowPrivateNetworkHTTP {
		msg += ", or http:// on a private network address or reserved local name (e.g. 192.168.x.x, *.home.arpa, *.internal)"
	}
	if allowPrivateScheme {
		msg += ", or a reverse-DNS private-use URI scheme (e.g. com.example.app://callback) for native public clients"
	}
	return msg + "."
}

func (s *Server) handleAdminCreateClient(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	cur := s.settings.Current()
	form, errMsg := parseClientForm(r, cur.AllowLoopbackHTTPRedirect, cur.AllowPrivateNetworkHTTPRedirect, cur.AllowPrivateSchemeRedirect)
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
	s.audit(r, evtClientCreated, auditEntry{actorUserID: actorID(r), clientID: c.ClientID, success: true})
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
	cur := s.settings.Current()
	form, errMsg := parseClientForm(r, cur.AllowLoopbackHTTPRedirect, cur.AllowPrivateNetworkHTTPRedirect, cur.AllowPrivateSchemeRedirect)
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
	s.audit(r, evtClientUpdated, auditEntry{actorUserID: actorID(r), clientID: existing.ClientID, success: true})
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
	s.audit(r, evtClientSecret, auditEntry{actorUserID: actorID(r), clientID: c.ClientID, success: true})
	s.renderClientDetail(w, r, http.StatusOK, c, secret, "")
}
