package enrollment

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pod32g/omni-identity/internal/pop"
)

// DefaultClientID is the built-in public client Omni ships for this agent.
const DefaultClientID = "omni-enrollment"

// Grant types and scopes (RFC 8628, RFC 7523, Omni's device:enroll scope).
const (
	grantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
	grantJWTBearer  = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	ScopeEnroll     = "openid profile email device:enroll"
	ScopeLogin      = "openid profile email offline_access"
)

// OAuthError is an RFC 6749 error response.
type OAuthError struct {
	Status      int
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

// IsOAuthError reports whether err is an OAuthError with the given code.
func IsOAuthError(err error, code string) bool {
	var oe *OAuthError
	return errors.As(err, &oe) && oe.Code == code
}

// Client talks to one Omni Identity issuer on behalf of one device key.
type Client struct {
	Issuer   string
	ClientID string
	Signer   Signer
	HTTP     *http.Client
	// Now is injectable for tests.
	Now func() time.Time

	endpoints *discovery
}

type discovery struct {
	Issuer                      string `json:"issuer"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

// Options configures NewClient.
type Options struct {
	Issuer            string
	ClientID          string
	Signer            Signer
	AllowInsecureHTTP bool   // permit an http:// issuer (private-network testing only)
	CAFile            string // extra PEM roots for a private CA
	Timeout           time.Duration
	// Transport overrides the HTTP transport (tests). CAFile is ignored then.
	Transport http.RoundTripper
}

// NewClient validates the issuer URL and builds the HTTP client.
func NewClient(opt Options) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(opt.Issuer, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid issuer URL %q", opt.Issuer)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !opt.AllowInsecureHTTP {
			return nil, errors.New("issuer uses http://; pass --allow-insecure-http only for private-network testing")
		}
	default:
		return nil, fmt.Errorf("issuer must be https:// (got %s://)", u.Scheme)
	}
	if opt.ClientID == "" {
		opt.ClientID = DefaultClientID
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 30 * time.Second
	}
	var rt http.RoundTripper
	tr, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		tr = tr.Clone()
	} else {
		tr = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	rt = tr
	if opt.Transport != nil {
		rt = opt.Transport
	} else if opt.CAFile != "" {
		pemBytes, err := os.ReadFile(opt.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("ca file contains no certificates")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &Client{
		Issuer:   u.String(),
		ClientID: opt.ClientID,
		Signer:   opt.Signer,
		HTTP:     &http.Client{Timeout: opt.Timeout, Transport: rt},
		Now:      time.Now,
	}, nil
}

func (c *Client) discover(ctx context.Context) (*discovery, error) {
	if c.endpoints != nil {
		return c.endpoints, nil
	}
	var d discovery
	if err := c.getJSON(ctx, c.Issuer+"/.well-known/openid-configuration", &d); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	if strings.TrimRight(d.Issuer, "/") != c.Issuer {
		return nil, fmt.Errorf("discovery issuer %q does not match %q", d.Issuer, c.Issuer)
	}
	if d.TokenEndpoint == "" || d.DeviceAuthorizationEndpoint == "" {
		return nil, errors.New("discovery: issuer does not advertise the device authorization grant")
	}
	c.endpoints = &d
	return &d, nil
}

// proof builds a DPoP proof for the request.
func (c *Client) proof(method, target, accessToken string) (string, error) {
	return pop.NewProof(c.Signer, method, target, accessToken, c.Now())
}

// DeviceAuthorization is the RFC 8628 §3.2 response.
type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// StartDeviceAuthorization begins a device grant. deviceToken, when non-empty,
// authenticates the request as an enrolled device (device-aware login).
func (c *Client) StartDeviceAuthorization(ctx context.Context, scope string, meta map[string]string, deviceToken string) (*DeviceAuthorization, error) {
	d, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{"client_id": {c.ClientID}, "scope": {scope}}
	for k, v := range meta {
		form.Set(k, v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.DeviceAuthorizationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if deviceToken != "" {
		if err := c.authorize(req, deviceToken); err != nil {
			return nil, err
		}
	}
	var out DeviceAuthorization
	if err := c.doJSON(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// TokenResponse is a token endpoint success body.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	DeviceTrust  string `json:"device_trust,omitempty"`
}

// PollDeviceCode performs one RFC 8628 §3.4 token request with a DPoP proof.
// deviceToken, when non-empty, must be the same device token used to start
// the grant. Callers loop on authorization_pending / slow_down.
func (c *Client) PollDeviceCode(ctx context.Context, deviceCode, deviceToken string) (*TokenResponse, error) {
	return c.tokenRequest(ctx, url.Values{
		"grant_type":  {grantDeviceCode},
		"device_code": {deviceCode},
		"client_id":   {c.ClientID},
	}, deviceToken)
}

// WaitForDeviceCode polls until the user approves/denies or the code expires,
// honouring interval and slow_down. onWait is called before each sleep.
func (c *Client) WaitForDeviceCode(ctx context.Context, da *DeviceAuthorization, deviceToken string, onWait func()) (*TokenResponse, error) {
	interval := time.Duration(da.Interval) * time.Second
	if interval < time.Second {
		interval = 5 * time.Second
	}
	deadline := c.Now().Add(time.Duration(da.ExpiresIn) * time.Second)
	for {
		tok, err := c.PollDeviceCode(ctx, da.DeviceCode, deviceToken)
		switch {
		case err == nil:
			return tok, nil
		case IsOAuthError(err, "authorization_pending"):
		case IsOAuthError(err, "slow_down"):
			interval += 5 * time.Second
		default:
			return nil, err
		}
		if c.Now().After(deadline) {
			return nil, errors.New("the code expired before it was approved")
		}
		if onWait != nil {
			onWait()
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
}

// DeviceToken performs the RFC 7523 jwt-bearer grant: it signs an assertion
// naming deviceID and returns a DPoP-bound device token.
func (c *Client) DeviceToken(ctx context.Context, deviceID string) (*TokenResponse, error) {
	assertion, err := pop.NewAssertion(c.Signer, c.Signer.Fingerprint(), deviceID, c.Issuer, c.Now(), 2*time.Minute, nil)
	if err != nil {
		return nil, err
	}
	return c.tokenRequest(ctx, url.Values{
		"grant_type": {grantJWTBearer},
		"assertion":  {assertion},
		"client_id":  {c.ClientID},
	}, "")
}

// RefreshToken redeems a DPoP-bound refresh token.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	return c.tokenRequest(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.ClientID},
	}, "")
}

func (c *Client) tokenRequest(ctx context.Context, form url.Values, deviceToken string) (*TokenResponse, error) {
	d, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if deviceToken != "" {
		// The proof must be bound (ath) to the device token presented alongside.
		if err := c.authorize(req, deviceToken); err != nil {
			return nil, err
		}
	} else {
		p, err := c.proof(http.MethodPost, d.TokenEndpoint, "")
		if err != nil {
			return nil, err
		}
		req.Header.Set("DPoP", p)
	}
	var out TokenResponse
	if err := c.doJSON(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// authorize attaches "Authorization: DPoP <token>" and a proof bound to it.
func (c *Client) authorize(req *http.Request, token string) error {
	target := req.URL.String()
	p, err := c.proof(req.Method, target, token)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", p)
	return nil
}

// Device is the wire representation returned by the device API.
type Device struct {
	ID            string `json:"device_id"`
	Name          string `json:"name"`
	Hostname      string `json:"hostname"`
	Platform      string `json:"platform"`
	Architecture  string `json:"architecture"`
	Fingerprint   string `json:"fingerprint"`
	Algorithm     string `json:"public_key_algorithm"`
	Status        string `json:"status"`
	TrustLevel    string `json:"trust_level"`
	OwnerSub      string `json:"owner_sub"`
	OwnerUsername string `json:"owner_username"`
	EnrolledAt    string `json:"enrolled_at"`
	LastSeenAt    string `json:"last_seen_at"`
	RevokedAt     string `json:"revoked_at"`
}

// Metadata describes the endpoint at enrollment.
type Metadata struct {
	Name         string `json:"name"`
	Hostname     string `json:"hostname"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
}

// Enroll registers this client's key as a device of the user who owns the
// DPoP-bound access token (docs §5.2 step 5).
func (c *Client) Enroll(ctx context.Context, accessToken string, meta Metadata) (*Device, error) {
	body, _ := json.Marshal(meta)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Issuer+"/api/v1/devices", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.authorize(req, accessToken); err != nil {
		return nil, err
	}
	var out Device
	if err := c.doJSON(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Me fetches the device's own record using a device token.
func (c *Client) Me(ctx context.Context, deviceToken string) (*Device, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Issuer+"/api/v1/devices/me", nil)
	if err != nil {
		return nil, err
	}
	if err := c.authorize(req, deviceToken); err != nil {
		return nil, err
	}
	var out Device
	if err := c.doJSON(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RotateKey replaces the registered key with newKey (docs §8). The current
// Signer authenticates the request; newKey signs the proof.
func (c *Client) RotateKey(ctx context.Context, deviceToken, deviceID string, newKey Signer) (*Device, error) {
	target := c.Issuer + "/api/v1/devices/me/key"
	proof, err := pop.NewAssertion(newKey, "", deviceID, target, c.Now(), 2*time.Minute,
		map[string]any{"old_jkt": c.Signer.Fingerprint()})
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]any{"jwk": newKey.JWK(), "proof": proof})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.authorize(req, deviceToken); err != nil {
		return nil, err
	}
	var out Device
	if err := c.doJSON(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Unenroll revokes the device on the server.
func (c *Client) Unenroll(ctx context.Context, deviceToken string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Issuer+"/api/v1/devices/me/unenroll", nil)
	if err != nil {
		return err
	}
	if err := c.authorize(req, deviceToken); err != nil {
		return err
	}
	return c.doJSON(req, &struct{}{})
}

// --- transport helpers ---

func (c *Client) getJSON(ctx context.Context, target string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	return c.doJSON(req, out)
}

func (c *Client) doJSON(req *http.Request, out any) error {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "omni-enrollment/"+Version)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return &ConnectivityError{Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		oe := &OAuthError{Status: resp.StatusCode}
		if json.Unmarshal(body, oe) != nil || oe.Code == "" {
			oe.Code = fmt.Sprintf("http_%d", resp.StatusCode)
			oe.Description = strings.TrimSpace(string(body))
		}
		return oe
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, out)
}

// ConnectivityError wraps transport failures so callers can distinguish
// "Omni unreachable" (keep the last known state) from "Omni said no".
type ConnectivityError struct{ Err error }

func (e *ConnectivityError) Error() string { return "omni identity unreachable: " + e.Err.Error() }
func (e *ConnectivityError) Unwrap() error { return e.Err }

// IsConnectivityError reports whether err is a transport failure.
func IsConnectivityError(err error) bool {
	var ce *ConnectivityError
	return errors.As(err, &ce)
}

// Version is stamped by the build (-ldflags "-X ...enrollment.Version=").
var Version = "0.1.0-dev"
