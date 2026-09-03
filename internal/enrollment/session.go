package enrollment

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Desktop sign-in (docs/OMNI-ENROLLMENT.md, "Desktop endpoints"). On a
// machine without the Linux login integration — a macOS desktop where the
// daemon runs as the desktop user — the user signs in explicitly: the agent
// runs the device-aware RFC 8628 grant authenticated by the device key and
// stores the resulting device-bound refresh token in the user cache the
// broker reads. Nothing is provisioned: no uid allocation, no local secret,
// no home directory; the caller's own uid is the identity.

// SignInEvent kinds reported by SignIn.
const (
	SignInVerification = "verification" // the link and code are ready
	SignInSignedIn     = "signed_in"    // the cache is written
)

// SignInEvent is what SignIn reports as the ceremony progresses.
type SignInEvent struct {
	Kind                    string `json:"kind"`
	VerificationURI         string `json:"verification_uri,omitempty"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	UserCode                string `json:"user_code,omitempty"`
	ExpiresIn               int    `json:"expires_in,omitempty"`
	Username                string `json:"username,omitempty"`
	Sub                     string `json:"sub,omitempty"`
	AMR                     string `json:"amr,omitempty"`
}

// SignIn signs the process owner uid in on this enrolled device: it obtains a
// device token, starts a device-bound login grant, reports the verification
// link through notify, waits for approval, checks the identity token, and
// stores a cache entry with the device-bound refresh token. Device-token
// errors are returned as-is so callers can tell an unreachable issuer
// (IsConnectivityError) from a revoked device (IsOAuthError).
func (a *Agent) SignIn(ctx context.Context, uid int, notify func(SignInEvent)) (*UserCache, error) {
	st, _, client, err := a.Open()
	if err != nil {
		return nil, err
	}
	devTok, err := client.DeviceToken(ctx, st.DeviceID)
	if err != nil {
		return nil, err
	}
	da, err := client.StartDeviceAuthorization(ctx, ScopeLogin, nil, devTok.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("could not start sign-in: %w", err)
	}
	if notify != nil {
		notify(SignInEvent{Kind: SignInVerification, VerificationURI: da.VerificationURI,
			VerificationURIComplete: da.VerificationURIComplete, UserCode: da.UserCode, ExpiresIn: da.ExpiresIn})
	}
	tok, err := client.WaitForDeviceCode(ctx, da, devTok.AccessToken, nil)
	if err != nil {
		return nil, fmt.Errorf("sign-in was not completed: %w", err)
	}
	claims, err := client.VerifyIDToken(ctx, tok.IDToken)
	if err != nil {
		return nil, errors.New("the identity token could not be verified")
	}
	sub, _ := claims["sub"].(string)
	preferred, _ := claims["preferred_username"].(string)
	deviceID, _ := claims["device_id"].(string)
	amr := amrString(claims["amr"])
	if sub == "" || preferred == "" {
		return nil, errors.New("the identity token names no user")
	}
	if deviceID != st.DeviceID {
		return nil, errors.New("the sign-in was not bound to this device")
	}
	if tok.RefreshToken == "" {
		return nil, errors.New("the sign-in granted no refresh token; the enrollment client must allow offline_access")
	}
	name := strings.ToLower(preferred)
	uc, err := a.LoadUserCache(name)
	if err != nil {
		return nil, err
	}
	if uc != nil && uc.Sub != "" && uc.Sub != sub {
		return nil, errors.New("this account belongs to a different Omni user")
	}
	if uc == nil {
		uc = &UserCache{Username: name}
	}
	now := time.Now().UTC()
	uc.Sub, uc.UID, uc.GID = sub, uid, uid
	uc.DeviceID, uc.AMR, uc.RefreshToken = deviceID, amr, tok.RefreshToken
	uc.LastOnlineAuth, uc.LastTrustRefresh = now, now
	uc.Revoked, uc.RevokedReason = false, ""
	if err := a.SaveUserCache(uc); err != nil {
		return nil, fmt.Errorf("could not save the credential cache: %w", err)
	}
	if notify != nil {
		notify(SignInEvent{Kind: SignInSignedIn, Username: uc.Username, Sub: uc.Sub, AMR: uc.AMR})
	}
	return uc, nil
}

// SignOut forgets every cache entry owned by uid, revoking its refresh token
// at Omni first (best effort: an unreachable issuer is not an error, the
// token is device-bound and dies with the cache; a refusal is reported as a
// warning). Nothing signed in is not an error.
func (a *Agent) SignOut(ctx context.Context, uid int) error {
	users, err := a.ListUserCaches()
	if err != nil {
		return err
	}
	var client *Client
	for _, uc := range users {
		if uc.UID != uid {
			continue
		}
		if uc.RefreshToken != "" {
			if client == nil {
				_, _, client, _ = a.Open()
			}
			if client != nil {
				if err := client.Revoke(ctx, uc.RefreshToken); err != nil && !IsConnectivityError(err) {
					fmt.Fprintf(a.Out, "warning: server-side revocation failed (%v); the token is still bound to this device\n", err)
				}
			}
		}
		if err := a.RemoveUserCache(uc.Username); err != nil {
			return err
		}
	}
	return nil
}

// Whoami returns the cache entry owned by uid with its secrets blanked, or
// (nil, nil) when that uid has not signed in.
func (a *Agent) Whoami(uid int) (*UserCache, error) {
	users, err := a.ListUserCaches()
	if err != nil {
		return nil, err
	}
	for _, uc := range users {
		if uc.UID == uid {
			out := *uc
			out.RefreshToken, out.SecretHash = "", ""
			return &out, nil
		}
	}
	return nil, nil
}
