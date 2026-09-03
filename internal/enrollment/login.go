package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pod32g/omni-identity/internal/pop"
	"golang.org/x/crypto/argon2"
)

// Linux login (docs/LINUX-LOGIN-ARCHITECTURE.md). The daemon runs a PAM
// conversation: online through Omni's device grant authenticated by the
// device key, offline through a locally chosen password whose Argon2id hash
// lives in a root-only cache, with an explicit validity window.

// LoginPolicy is the operator-tunable offline policy.
type LoginPolicy struct {
	OfflineValidity time.Duration // offline login allowed while now < last_trust_refresh + this
	LoginShell      string
	MinLocalSecret  int
}

// DefaultLoginPolicy is a homelab-friendly default: a week offline.
var DefaultLoginPolicy = LoginPolicy{OfflineValidity: 7 * 24 * time.Hour, LoginShell: "/bin/bash", MinLocalSecret: 8}

// UserCache is the per-user offline record. It never contains an Omni or
// LDAP password; secret_hash is the hash of a password the user chose for
// this machine only.
type UserCache struct {
	Username         string    `json:"username"`
	Sub              string    `json:"sub"`
	UID              int       `json:"uid"`
	GID              int       `json:"gid"`
	Home             string    `json:"home"`
	SecretHash       string    `json:"secret_hash,omitempty"`
	LastOnlineAuth   time.Time `json:"last_online_auth"`
	LastTrustRefresh time.Time `json:"last_trust_refresh"`
	DeviceID         string    `json:"device_id"`
	AMR              string    `json:"amr,omitempty"`
	RefreshToken     string    `json:"refresh_token,omitempty"` // device- and DPoP-bound; useless without the device key
	Revoked          bool      `json:"revoked"`
	RevokedReason    string    `json:"revoked_reason,omitempty"`
}

// Conversation is the PAM-side of a login: messages out, answers in.
type Conversation interface {
	Info(text string)
	Error(text string)
	Prompt(text string, echo bool) (string, error)
}

// Provisioner creates local accounts. The Linux implementation runs useradd;
// tests use a fake.
type Provisioner interface {
	// Lookup reports whether a local account exists and, if so, its uid.
	Lookup(name string) (uid int, exists bool, err error)
	// UIDInUse reports whether a uid is already allocated (to any name).
	UIDInUse(uid int) (bool, error)
	// Create makes the account with a locked password field.
	Create(name string, uid, gid int, home, shell, gecos string) error
}

// Verdict is the PAM outcome.
type Verdict int

const (
	VerdictFail   Verdict = iota
	VerdictOK             // authenticated
	VerdictIgnore         // not an Omni-managed user: let pam_unix decide
)

// Login errors surfaced to the user (never token or key material).
var (
	errNotApprovedForUser = errors.New("the sign-in was approved by a different account")
	errBadUsername        = errors.New("username is not a valid Linux account name")
)

var validLinuxName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// usersDir is where per-user caches live under the state dir.
func (a *Agent) usersDir() string { return filepath.Join(a.StateDir, "users") }

// LoadUserCache reads a user's offline record (nil, nil when absent).
func (a *Agent) LoadUserCache(name string) (*UserCache, error) {
	raw, err := os.ReadFile(filepath.Join(a.usersDir(), name+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var uc UserCache
	if err := json.Unmarshal(raw, &uc); err != nil {
		return nil, err
	}
	return &uc, nil
}

// SaveUserCache writes the record atomically (0600 root).
func (a *Agent) SaveUserCache(uc *UserCache) error {
	if err := os.MkdirAll(a.usersDir(), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(uc, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(a.usersDir(), uc.Username+".json")
	if err := os.WriteFile(path+".tmp", raw, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// ListUserCaches returns every cached user.
func (a *Agent) ListUserCaches() ([]*UserCache, error) {
	entries, err := os.ReadDir(a.usersDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*UserCache
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		uc, err := a.LoadUserCache(strings.TrimSuffix(e.Name(), ".json"))
		if err == nil && uc != nil {
			out = append(out, uc)
		}
	}
	return out, nil
}

// --- local secret (Argon2id) ---

const argonTime, argonMemory, argonThreads, argonKeyLen = 3, 64 * 1024, 4, 32

func hashLocalSecret(secret string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	key := argon2.IDKey([]byte(secret), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

func verifyLocalSecret(secret, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(secret), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// --- uid mapping ---

const (
	uidRangeStart = 200000
	uidRangeSize  = 100000
)

// uidFor derives a deterministic uid from the stable Omni subject.
func uidFor(sub string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(sub))
	return uidRangeStart + int(h.Sum32()%uidRangeSize)
}

// --- the conversation ---

// LoginContext is the per-session input to Login.
type LoginContext struct {
	Username string
	Service  string
	RHost    string
}

// offlineAllowed reports whether a cache entry may authenticate offline now.
func (a *Agent) offlineAllowed(uc *UserCache, now time.Time, pol LoginPolicy) (bool, string) {
	switch {
	case uc == nil:
		return false, "no offline credentials for this account on this machine"
	case uc.Revoked:
		return false, "this account's access from this device was revoked; sign in online"
	case uc.SecretHash == "":
		return false, "no local password set yet; sign in online first"
	case now.After(uc.LastTrustRefresh.Add(pol.OfflineValidity)):
		return false, "offline access expired; sign in online to renew it"
	}
	if rt, err := ReadStatus(a.RuntimeDir); err == nil && rt.Status == "revoked" {
		return false, "this device was revoked; sign in online"
	}
	return true, ""
}

// Login runs the whole PAM conversation for one user and returns the verdict.
// It is the only place where the online and offline paths meet.
func (a *Agent) Login(ctx context.Context, conv Conversation, lc LoginContext, prov Provisioner, pol LoginPolicy) Verdict {
	name := strings.ToLower(strings.TrimSpace(lc.Username))
	if !validLinuxName.MatchString(name) {
		return VerdictIgnore
	}
	uc, err := a.LoadUserCache(name)
	if err != nil {
		conv.Error("omni: could not read the local credential cache")
		return VerdictFail
	}
	if uc == nil {
		// A local account we do not manage (root, omni-recovery, …): not ours.
		if _, exists, _ := prov.Lookup(name); exists {
			return VerdictIgnore
		}
	}
	now := time.Now().UTC()

	if ok, _ := a.offlineAllowed(uc, now, pol); ok {
		pw, err := conv.Prompt("Local password (leave empty to sign in with Omni Identity): ", false)
		if err != nil {
			return VerdictFail
		}
		if pw != "" {
			if verifyLocalSecret(pw, uc.SecretHash) {
				return VerdictOK
			}
			conv.Error("Invalid local password.")
			return VerdictFail
		}
	}
	return a.onlineLogin(ctx, conv, name, uc, prov, pol, now)
}

func (a *Agent) onlineLogin(ctx context.Context, conv Conversation, name string, uc *UserCache, prov Provisioner, pol LoginPolicy, now time.Time) Verdict {
	st, _, client, err := a.Open()
	if err != nil {
		conv.Error("omni: this machine is not enrolled")
		return VerdictFail
	}
	devTok, err := client.DeviceToken(ctx, st.DeviceID)
	if err != nil {
		if IsConnectivityError(err) {
			if _, why := a.offlineAllowed(uc, now, pol); why != "" {
				conv.Error("Omni Identity is unreachable and " + why + ".")
			} else {
				conv.Error("Omni Identity is unreachable.")
			}
		} else {
			conv.Error("omni: this device is no longer trusted (" + err.Error() + "); re-enroll it.")
		}
		return VerdictFail
	}
	da, err := client.StartDeviceAuthorization(ctx, ScopeLogin, nil, devTok.AccessToken)
	if err != nil {
		conv.Error("omni: could not start sign-in: " + err.Error())
		return VerdictFail
	}
	// The link is delivered as part of a prompt rather than a bare info
	// message: OpenSSH's keyboard-interactive PAM bridge only shows info text
	// together with the next prompt, so a bare message would arrive after the
	// approval it asks for. Polling runs concurrently; Enter merely
	// acknowledges the prompt.
	wctx, cancel := context.WithTimeout(ctx, time.Duration(da.ExpiresIn+10)*time.Second)
	defer cancel()
	type pollResult struct {
		tok *TokenResponse
		err error
	}
	polled := make(chan pollResult, 1)
	go func() {
		tok, err := client.WaitForDeviceCode(wctx, da, devTok.AccessToken, nil)
		polled <- pollResult{tok, err}
	}()
	prompt := fmt.Sprintf("Sign in with Omni Identity on any device:\n  %s\n  (code %s, expires in %d minutes)\nPress Enter after approving: ",
		da.VerificationURIComplete, da.UserCode, da.ExpiresIn/60)
	if _, err := conv.Prompt(prompt, true); err != nil {
		cancel()
		return VerdictFail
	}
	res := <-polled
	tok, err := res.tok, res.err
	if err != nil {
		conv.Error("Sign-in was not completed: " + err.Error())
		return VerdictFail
	}
	claims, err := client.VerifyIDToken(ctx, tok.IDToken)
	if err != nil {
		conv.Error("omni: the identity token could not be verified")
		return VerdictFail
	}
	sub, _ := claims["sub"].(string)
	preferred, _ := claims["preferred_username"].(string)
	deviceID, _ := claims["device_id"].(string)
	amr := amrString(claims["amr"])
	if !strings.EqualFold(preferred, name) || sub == "" {
		conv.Error(errNotApprovedForUser.Error() + " (" + preferred + ")")
		return VerdictFail
	}
	if deviceID != st.DeviceID {
		conv.Error("omni: the sign-in was not bound to this device")
		return VerdictFail
	}
	if uc != nil && uc.Sub != "" && uc.Sub != sub {
		conv.Error("omni: this local account belongs to a different Omni user")
		return VerdictFail
	}

	// Provision the local account on first login.
	uid, exists, err := prov.Lookup(name)
	if err != nil {
		conv.Error("omni: account lookup failed")
		return VerdictFail
	}
	if !exists {
		uid = uidFor(sub)
		for i := 0; i < 1000; i++ {
			inUse, err := prov.UIDInUse(uid)
			if err != nil {
				conv.Error("omni: uid lookup failed")
				return VerdictFail
			}
			if !inUse {
				break
			}
			uid++
		}
		home := "/home/" + name
		if err := prov.Create(name, uid, uid, home, pol.LoginShell, "Omni Identity "+sub); err != nil {
			conv.Error("omni: could not create the local account: " + err.Error())
			return VerdictFail
		}
		conv.Info("Local account " + name + " created.")
	}

	if uc == nil {
		uc = &UserCache{Username: name, Sub: sub, UID: uid, GID: uid, Home: "/home/" + name}
	}
	if uc.SecretHash == "" {
		if !a.chooseLocalSecret(conv, uc, pol) {
			return VerdictFail
		}
	}
	uc.Sub, uc.DeviceID, uc.AMR = sub, deviceID, amr
	uc.LastOnlineAuth, uc.LastTrustRefresh = now, now
	uc.Revoked, uc.RevokedReason = false, ""
	if tok.RefreshToken != "" {
		uc.RefreshToken = tok.RefreshToken
	}
	if err := a.SaveUserCache(uc); err != nil {
		conv.Error("omni: could not save the offline credential cache")
		return VerdictFail
	}
	return VerdictOK
}

// chooseLocalSecret asks the user for the machine-local offline password.
func (a *Agent) chooseLocalSecret(conv Conversation, uc *UserCache, pol LoginPolicy) bool {
	conv.Info("Choose a local password for this machine. It is used only when Omni Identity is unreachable and is never sent anywhere.")
	for attempt := 0; attempt < 3; attempt++ {
		p1, err := conv.Prompt("New local password: ", false)
		if err != nil {
			return false
		}
		if len(p1) < pol.MinLocalSecret {
			conv.Error(fmt.Sprintf("Use at least %d characters.", pol.MinLocalSecret))
			continue
		}
		p2, err := conv.Prompt("Retype local password: ", false)
		if err != nil {
			return false
		}
		if p1 != p2 {
			conv.Error("The passwords do not match.")
			continue
		}
		uc.SecretHash = hashLocalSecret(p1)
		return true
	}
	return false
}

// EnsureOwnerAccount creates the enrolling user's local account (and a cache
// entry without a local password) ahead of their first login. sshd looks the
// user up with getpwnam before running PAM and refuses to authenticate an
// unknown user even when PAM succeeds, so just-in-time creation during the
// first SSH login is impossible without an NSS module; pre-provisioning the
// owner keeps the PoC free of one. Other users are provisioned at their first
// console login (docs/LINUX-LOGIN-ARCHITECTURE.md §4).
func (a *Agent) EnsureOwnerAccount(st *State, prov Provisioner, pol LoginPolicy) error {
	if prov == nil || st == nil || st.OwnerUsername == "" || st.OwnerSub == "" {
		return nil
	}
	name := strings.ToLower(st.OwnerUsername)
	if !validLinuxName.MatchString(name) {
		return fmt.Errorf("%w: %q", errBadUsername, st.OwnerUsername)
	}
	if pol.LoginShell == "" {
		pol = DefaultLoginPolicy
	}
	uc, err := a.LoadUserCache(name)
	if err != nil {
		return err
	}
	uid, exists, err := prov.Lookup(name)
	if err != nil {
		return err
	}
	if exists && uc == nil {
		// A pre-existing local account of the same name is not ours to take over.
		return fmt.Errorf("local account %q already exists and is not Omni-managed", name)
	}
	if !exists {
		uid = uidFor(st.OwnerSub)
		for i := 0; i < 1000; i++ {
			inUse, err := prov.UIDInUse(uid)
			if err != nil {
				return err
			}
			if !inUse {
				break
			}
			uid++
		}
		if err := prov.Create(name, uid, uid, "/home/"+name, pol.LoginShell, "Omni Identity "+st.OwnerSub); err != nil {
			return err
		}
	}
	if uc == nil {
		uc = &UserCache{Username: name, Sub: st.OwnerSub, UID: uid, GID: uid, Home: "/home/" + name, DeviceID: st.DeviceID}
		return a.SaveUserCache(uc)
	}
	return nil
}

// Account implements the PAM account check: managed users must not be revoked.
func (a *Agent) Account(name string, prov Provisioner, pol LoginPolicy) Verdict {
	name = strings.ToLower(strings.TrimSpace(name))
	uc, err := a.LoadUserCache(name)
	if err != nil || uc == nil {
		return VerdictIgnore
	}
	if uc.Revoked {
		return VerdictFail
	}
	return VerdictOK
}

// RefreshUsers redeems each cached user's device-bound refresh token to
// extend offline validity, marking entries revoked when Omni refuses. Called
// by the daemon on every renewal cycle. Connectivity failures change nothing.
func (a *Agent) RefreshUsers(ctx context.Context, client *Client, logf func(string, ...any)) {
	users, err := a.ListUserCaches()
	if err != nil {
		return
	}
	for _, uc := range users {
		if uc.RefreshToken == "" || uc.Revoked {
			continue
		}
		tok, err := client.RefreshToken(ctx, uc.RefreshToken)
		switch {
		case err == nil:
			uc.LastTrustRefresh = time.Now().UTC()
			if tok.RefreshToken != "" {
				uc.RefreshToken = tok.RefreshToken
			}
			logf("trust refreshed for %s", uc.Username)
		case IsConnectivityError(err):
			continue
		default:
			uc.Revoked, uc.RevokedReason = true, err.Error()
			uc.RefreshToken = ""
			logf("trust refresh refused for %s: %v (offline login disabled)", uc.Username, err)
		}
		_ = a.SaveUserCache(uc)
	}
}

// --- ID token verification ---

// VerifyIDToken checks an ID token from the issuer against its JWKS: signature,
// issuer, audience (this client), expiry.
func (c *Client) VerifyIDToken(ctx context.Context, raw string) (jwt.MapClaims, error) {
	if raw == "" {
		return nil, errors.New("missing id_token")
	}
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := c.getJSON(ctx, c.Issuer+"/jwks.json", &jwks); err != nil {
		return nil, err
	}
	claims := jwt.MapClaims{}
	_, err := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "EdDSA", "ES256"}),
		jwt.WithIssuer(c.Issuer),
		jwt.WithAudience(c.ClientID),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(c.Now),
	).ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		for _, k := range jwks.Keys {
			var meta struct {
				Kid string `json:"kid"`
			}
			_ = json.Unmarshal(k, &meta)
			if meta.Kid != kid {
				continue
			}
			j, err := pop.ParseJWK(k)
			if err != nil {
				return nil, err
			}
			return j.PublicKey()
		}
		return nil, fmt.Errorf("unknown key id %q", kid)
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func amrString(v any) string {
	arr, _ := v.([]any)
	parts := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

// HashLocalSecretForTest exposes the local-secret hash for tests.
func HashLocalSecretForTest(secret string) string { return hashLocalSecret(secret) }
