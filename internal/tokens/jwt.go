package tokens

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Profile carries the identity claims placed into an ID token.
type Profile struct {
	Email             string
	EmailVerified     bool
	PreferredUsername string
	Name              string
}

// IssuerConfig supplies the issuer string and token lifetimes at use-time,
// allowing them to be changed live (e.g. from admin-editable settings).
type IssuerConfig interface {
	Issuer() string
	AccessTTL() time.Duration
	IDTTL() time.Duration
}

// Issuer mints and verifies signed JWTs using a KeyManager's active signer.
type Issuer struct {
	km        *KeyManager
	issuer    string
	accessTTL time.Duration
	idTTL     time.Duration
	cfg       IssuerConfig // when non-nil, overrides the static fields live
}

// NewIssuer builds an Issuer with static issuer/TTLs.
func NewIssuer(km *KeyManager, issuer string, accessTTL, idTTL time.Duration) *Issuer {
	return &Issuer{km: km, issuer: issuer, accessTTL: accessTTL, idTTL: idTTL}
}

// SetConfigProvider makes the Issuer read its issuer and TTLs from cfg at
// use-time instead of the static fields.
func (i *Issuer) SetConfigProvider(cfg IssuerConfig) { i.cfg = cfg }

func (i *Issuer) issuerName() string {
	if i.cfg != nil {
		return i.cfg.Issuer()
	}
	return i.issuer
}

// AccessTTL reports the access-token lifetime (for expires_in responses).
func (i *Issuer) AccessTTL() time.Duration {
	if i.cfg != nil {
		return i.cfg.AccessTTL()
	}
	return i.accessTTL
}

// IDTTL reports the ID-token lifetime.
func (i *Issuer) IDTTL() time.Duration {
	if i.cfg != nil {
		return i.cfg.IDTTL()
	}
	return i.idTTL
}

// IssueAccessToken mints a signed access-token JWT.
func (i *Issuer) IssueAccessToken(subject, audience, scope string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":       i.issuerName(),
		"sub":       subject,
		"aud":       audience,
		"iat":       now.Unix(),
		"exp":       now.Add(i.AccessTTL()).Unix(),
		"scope":     scope,
		"token_use": "access",
	}
	return i.sign(claims)
}

// IssueIDToken mints a signed ID-token JWT carrying identity claims.
func (i *Issuer) IssueIDToken(subject, audience string, p Profile, nonce string, authTime time.Time) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":                i.issuerName(),
		"sub":                subject,
		"aud":                audience,
		"iat":                now.Unix(),
		"exp":                now.Add(i.IDTTL()).Unix(),
		"auth_time":          authTime.Unix(),
		"email":              p.Email,
		"email_verified":     p.EmailVerified,
		"preferred_username": p.PreferredUsername,
		"name":               p.Name,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return i.sign(claims)
}

func (i *Issuer) sign(claims jwt.MapClaims) (string, error) {
	s := i.km.DefaultSigner()
	if s == nil {
		return "", fmt.Errorf("no signing key available")
	}
	method, err := signingMethod(s.Alg)
	if err != nil {
		return "", err
	}
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = s.KID
	return tok.SignedString(s.Key)
}

// VerifiedToken holds the validated claims of a token.
type VerifiedToken struct {
	Subject           string
	Audience          string
	Scope             string
	Email             string
	PreferredUsername string
	Claims            jwt.MapClaims
}

// IsAccessToken reports whether the token was minted as an access token.
func (v *VerifiedToken) IsAccessToken() bool {
	return v.Claims["token_use"] == "access"
}

// Verify checks the signature (by kid), allowed algorithms, issuer, and expiry,
// returning the validated claims.
func (i *Issuer) Verify(tokenStr string) (*VerifiedToken, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		pub, ok := i.km.PublicKey(kid)
		if !ok {
			return nil, fmt.Errorf("unknown key id %q", kid)
		}
		return pub, nil
	},
		jwt.WithValidMethods([]string{AlgRS256, AlgEdDSA}),
		jwt.WithIssuer(i.issuerName()),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}

	vt := &VerifiedToken{Claims: claims}
	vt.Subject, _ = claims["sub"].(string)
	vt.Scope, _ = claims["scope"].(string)
	vt.Email, _ = claims["email"].(string)
	vt.PreferredUsername, _ = claims["preferred_username"].(string)
	vt.Audience = audienceString(claims)
	return vt, nil
}

// ParseIDTokenHint validates an id_token_hint for RP-initiated logout. It
// checks the signature (by kid), allowed algorithms, and issuer, but tolerates
// an expired token, since the hint is commonly presented after the session has
// already lapsed. Returns the subject and audience for revocation/redirect.
func (i *Issuer) ParseIDTokenHint(tokenStr string) (*VerifiedToken, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		pub, ok := i.km.PublicKey(kid)
		if !ok {
			return nil, fmt.Errorf("unknown key id %q", kid)
		}
		return pub, nil
	},
		jwt.WithValidMethods([]string{AlgRS256, AlgEdDSA}),
		jwt.WithoutClaimsValidation(), // tolerate expiry; we verify issuer manually
	)
	if err != nil {
		return nil, err
	}
	if iss, _ := claims["iss"].(string); iss != i.issuerName() {
		return nil, fmt.Errorf("issuer mismatch")
	}
	vt := &VerifiedToken{Claims: claims}
	vt.Subject, _ = claims["sub"].(string)
	vt.Audience = audienceString(claims)
	return vt, nil
}

func audienceString(claims jwt.MapClaims) string {
	switch v := claims["aud"].(type) {
	case string:
		return v
	case []any:
		if len(v) > 0 {
			s, _ := v[0].(string)
			return s
		}
	}
	return ""
}

func signingMethod(alg string) (jwt.SigningMethod, error) {
	switch alg {
	case AlgRS256:
		return jwt.SigningMethodRS256, nil
	case AlgEdDSA:
		return jwt.SigningMethodEdDSA, nil
	default:
		return nil, fmt.Errorf("unsupported signing alg %q", alg)
	}
}
