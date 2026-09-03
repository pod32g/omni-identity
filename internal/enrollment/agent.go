package enrollment

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

// Agent bundles the on-disk state, key, and client for the CLI and daemon.
type Agent struct {
	StateDir   string
	RuntimeDir string
	Out        io.Writer
	// Transport overrides the HTTP transport (tests only).
	Transport http.RoundTripper
	// Provisioner creates local accounts (SystemProvisioner in the CLI; a fake
	// in tests). nil disables owner pre-provisioning.
	Provisioner Provisioner
	// Policy is the login policy used for pre-provisioning.
	Policy LoginPolicy
}

// Config is what the CLI resolves from flags/env/config file.
type Config struct {
	Issuer            string
	ClientID          string
	StateDir          string
	RuntimeDir        string
	Name              string
	AllowInsecureHTTP bool
	CAFile            string
	// Linux login policy (docs/LINUX-LOGIN-ARCHITECTURE.md §3.2).
	OfflineValidity time.Duration
	LoginShell      string
	// RefreshInterval caps the daemon's renewal/trust-refresh cadence.
	RefreshInterval time.Duration
	// QR controls the terminal QR code under the verification URL: dark
	// (default), light, or off.
	QR string
}

func (c Config) qrMode() string {
	if c.QR == "" {
		return QRDark
	}
	return c.QR
}

// Policy renders the login policy from the config with defaults applied.
func (c Config) Policy() LoginPolicy {
	pol := DefaultLoginPolicy
	if c.OfflineValidity > 0 {
		pol.OfflineValidity = c.OfflineValidity
	}
	if c.LoginShell != "" {
		pol.LoginShell = c.LoginShell
	}
	if c.QR != "" {
		pol.QR = c.QR
	}
	return pol
}

// Defaults for a Linux host.
const (
	DefaultStateDir   = "/var/lib/omni-enrollment"
	DefaultRuntimeDir = "/run/omni-enrollment"
)

// LocalMetadata collects the endpoint description sent at enrollment.
func LocalMetadata(name string) Metadata {
	host, _ := os.Hostname()
	if name == "" {
		name = host
	}
	return Metadata{Name: name, Hostname: host, Platform: runtime.GOOS, Architecture: runtime.GOARCH}
}

// Enroll runs the full ceremony (docs §5.2): generate a key, start an RFC 8628
// grant, show the user the verification URL, poll with DPoP, register the key.
func (a *Agent) Enroll(ctx context.Context, cfg Config) (*State, error) {
	if _, err := LoadState(a.StateDir); err == nil {
		return nil, errors.New("this machine is already enrolled (run `omni-enrollment unenroll` first)")
	}
	fmt.Fprintln(a.Out, "Generating device identity...")
	key, err := GenerateKey(a.StateDir, false)
	if err != nil {
		return nil, err
	}
	client, err := NewClient(Options{Issuer: cfg.Issuer, ClientID: cfg.ClientID, Signer: key,
		AllowInsecureHTTP: cfg.AllowInsecureHTTP, CAFile: cfg.CAFile, Transport: a.Transport})
	if err != nil {
		return nil, err
	}
	meta := LocalMetadata(cfg.Name)
	fmt.Fprintf(a.Out, "\nDevice:\n    name:        %s\n    hostname:    %s\n    platform:    %s (%s)\n    fingerprint: %s\n\n",
		meta.Name, meta.Hostname, meta.Platform, meta.Architecture, key.Fingerprint())

	da, err := client.StartDeviceAuthorization(ctx, ScopeEnroll,
		map[string]string{"device_name": meta.Name, "device_platform": meta.Platform}, "")
	if err != nil {
		return nil, fmt.Errorf("start enrollment: %w", err)
	}
	fmt.Fprintf(a.Out, "Authenticate with Omni Identity:\n\n    %s\n\n    (or open %s and enter the code %s)\n\n",
		da.VerificationURIComplete, da.VerificationURI, da.UserCode)
	if qr, err := RenderQR(da.VerificationURIComplete, cfg.qrMode()); err == nil && qr != "" {
		fmt.Fprintln(a.Out, qr)
	}
	fmt.Fprint(a.Out, "Waiting for approval...")

	tok, err := client.WaitForDeviceCode(ctx, da, "", func() { fmt.Fprint(a.Out, ".") })
	fmt.Fprintln(a.Out)
	if err != nil {
		_ = RemoveState(a.StateDir)
		return nil, fmt.Errorf("enrollment was not approved: %w", err)
	}
	dev, err := client.Enroll(ctx, tok.AccessToken, meta)
	if err != nil {
		_ = RemoveState(a.StateDir)
		return nil, fmt.Errorf("register device: %w", err)
	}
	enrolledAt, _ := time.Parse(time.RFC3339, dev.EnrolledAt)
	st := &State{
		Issuer: client.Issuer, ClientID: client.ClientID, DeviceID: dev.ID, Fingerprint: dev.Fingerprint,
		Name: dev.Name, OwnerSub: dev.OwnerSub, OwnerUsername: dev.OwnerUsername, EnrolledAt: enrolledAt,
		Status: dev.Status, LastCheckedAt: time.Now().UTC(),
		AllowInsecureHTTP: cfg.AllowInsecureHTTP, CAFile: cfg.CAFile,
	}
	if err := SaveState(a.StateDir, st); err != nil {
		return nil, err
	}
	fmt.Fprintf(a.Out, "Enrolled as %s (device id %s).\n", dev.OwnerUsername, dev.ID)
	if a.Provisioner != nil {
		if err := a.EnsureOwnerAccount(st, a.Provisioner, a.policy()); err != nil {
			fmt.Fprintf(a.Out, "warning: could not pre-provision the local account for %s: %v\n", dev.OwnerUsername, err)
		} else {
			fmt.Fprintf(a.Out, "Local account %s is ready; sign in with `ssh %s@<host>` to finish setup.\n", dev.OwnerUsername, dev.OwnerUsername)
		}
	}
	return st, nil
}

func (a *Agent) policy() LoginPolicy {
	if a.Policy.OfflineValidity <= 0 {
		return DefaultLoginPolicy
	}
	return a.Policy
}

// Open loads the enrolled state, key, and a client for it.
func (a *Agent) Open() (*State, Signer, *Client, error) {
	st, err := LoadState(a.StateDir)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := LoadKey(a.StateDir)
	if err != nil {
		return nil, nil, nil, err
	}
	if key.Fingerprint() != st.Fingerprint {
		return nil, nil, nil, fmt.Errorf("device key fingerprint %s does not match enrollment record %s", key.Fingerprint(), st.Fingerprint)
	}
	client, err := NewClient(Options{Issuer: st.Issuer, ClientID: st.ClientID, Signer: key,
		AllowInsecureHTTP: st.AllowInsecureHTTP, CAFile: st.CAFile, Transport: a.Transport})
	if err != nil {
		return nil, nil, nil, err
	}
	return st, key, client, nil
}

// Renew obtains a fresh device token, updates the persisted status, and
// returns the token. A revocation is recorded as sticky state.
func (a *Agent) Renew(ctx context.Context) (*State, *TokenResponse, error) {
	st, _, client, err := a.Open()
	if err != nil {
		return nil, nil, err
	}
	tok, err := client.DeviceToken(ctx, st.DeviceID)
	now := time.Now().UTC()
	status := &Status{DeviceID: st.DeviceID, LastCheckedAt: now}
	switch {
	case err == nil:
		st.Status = "active"
		st.LastCheckedAt = now
		status.Status, status.TrustLevel, status.IssuerReachable = "active", tok.DeviceTrust, true
		status.LastRenewedAt = now
		status.TokenExpiresAt = now.Add(time.Duration(tok.ExpiresIn) * time.Second)
	case IsConnectivityError(err):
		status.Status, status.IssuerReachable, status.LastError = st.Status, false, err.Error()
	default:
		// Omni answered and refused: treat as revoked/unknown, never as active.
		st.Status = "revoked"
		st.LastCheckedAt = now
		status.Status, status.IssuerReachable, status.LastError = "revoked", true, err.Error()
	}
	_ = SaveState(a.StateDir, st)
	_ = WriteStatus(a.RuntimeDir, status)
	if err != nil {
		return st, nil, err
	}
	return st, tok, nil
}

// RotateKey generates a new key, rotates it on the server, then commits it to
// disk. Requires proof of possession of the current key (device token).
func (a *Agent) RotateKey(ctx context.Context) (*State, error) {
	st, _, client, err := a.Open()
	if err != nil {
		return nil, err
	}
	tok, err := client.DeviceToken(ctx, st.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("authenticate with current key: %w", err)
	}
	newKey, priv, err := NewEphemeralKey()
	if err != nil {
		return nil, err
	}
	dev, err := client.RotateKey(ctx, tok.AccessToken, st.DeviceID, newKey)
	if err != nil {
		return nil, fmt.Errorf("rotate key: %w", err)
	}
	if err := CommitKey(a.StateDir, priv); err != nil {
		return nil, fmt.Errorf("server accepted the new key but it could not be saved locally; re-enroll: %w", err)
	}
	st.Fingerprint = dev.Fingerprint
	st.LastCheckedAt = time.Now().UTC()
	if err := SaveState(a.StateDir, st); err != nil {
		return nil, err
	}
	return st, nil
}

// Unenroll revokes the device server-side (best effort) and wipes local state.
func (a *Agent) Unenroll(ctx context.Context) error {
	st, _, client, err := a.Open()
	if err != nil {
		if errors.Is(err, ErrNotEnrolled) || errors.Is(err, ErrNoKey) {
			return RemoveState(a.StateDir)
		}
		return err
	}
	if tok, err := client.DeviceToken(ctx, st.DeviceID); err == nil {
		if err := client.Unenroll(ctx, tok.AccessToken); err != nil && !IsOAuthError(err, "invalid_grant") {
			fmt.Fprintf(a.Out, "warning: server-side revocation failed (%v); revoke it under My Devices\n", err)
		}
	} else {
		fmt.Fprintf(a.Out, "warning: could not authenticate to revoke server-side (%v); revoke it under My Devices\n", err)
	}
	return RemoveState(a.StateDir)
}

// DaemonOptions tunes RunDaemon.
type DaemonOptions struct {
	Provisioner Provisioner
	Policy      LoginPolicy
	// RefreshEvery caps the renewal interval (0 = half the device-token
	// lifetime). Also drives the per-user trust refresh.
	RefreshEvery time.Duration
	// ServePAM starts the PAM socket (Linux login integration).
	ServePAM bool
}

// RunDaemon renews the device token on a schedule (half its lifetime, at
// least every minute, backing off while Omni is unreachable), refreshes the
// cached Linux users' trust, serves the PAM socket, and keeps status.json
// current. It exits when ctx is cancelled. It deliberately does nothing else:
// no remote commands, no policy, no MDM.
func (a *Agent) RunDaemon(ctx context.Context, opt DaemonOptions, logf func(string, ...any)) error {
	if _, err := LoadState(a.StateDir); err != nil {
		return err
	}
	if opt.Provisioner == nil {
		opt.Provisioner = SystemProvisioner{}
	}
	if opt.Policy.OfflineValidity <= 0 {
		opt.Policy = DefaultLoginPolicy
	}
	if st, err := LoadState(a.StateDir); err == nil {
		// sshd resolves the user before PAM runs, so the owner's account must
		// already exist for a first SSH login (docs/LINUX-LOGIN-ARCHITECTURE.md §4).
		if err := a.EnsureOwnerAccount(st, opt.Provisioner, opt.Policy); err != nil {
			logf("pre-provision owner account: %v", err)
		}
	}
	if opt.ServePAM {
		go func() {
			if err := a.ServePAM(ctx, opt.Provisioner, opt.Policy, logf); err != nil {
				logf("pam socket: %v", err)
			}
		}()
	}
	backoff := time.Minute
	for {
		st, tok, err := a.Renew(ctx)
		var wait time.Duration
		switch {
		case err == nil:
			wait = time.Duration(tok.ExpiresIn) * time.Second / 2
			if wait < time.Minute {
				wait = time.Minute
			}
			backoff = time.Minute
			logf("device token renewed device=%s trust=%s next=%s", st.DeviceID, tok.DeviceTrust, wait)
			if _, _, client, oerr := a.Open(); oerr == nil {
				a.RefreshUsers(ctx, client, logf)
			}
		case IsConnectivityError(err):
			wait = backoff
			if backoff < 15*time.Minute {
				backoff *= 2
			}
			logf("omni identity unreachable, retrying in %s: %v", wait, err)
		default:
			// Refused: revoked (or disabled owner). Re-check slowly; the operator
			// must re-enroll. Local login policy reads status.json.
			wait = 15 * time.Minute
			logf("device credentials refused (status=%s): %v", st.Status, err)
		}
		if opt.RefreshEvery > 0 && wait > opt.RefreshEvery {
			wait = opt.RefreshEvery
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// Describe renders a human-readable status.
func Describe(st *State, rt *Status) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Device:      %s (%s)\n", st.Name, st.DeviceID)
	fmt.Fprintf(&b, "Issuer:      %s\n", st.Issuer)
	fmt.Fprintf(&b, "Owner:       %s\n", st.OwnerUsername)
	fmt.Fprintf(&b, "Fingerprint: %s\n", st.Fingerprint)
	fmt.Fprintf(&b, "Enrolled:    %s\n", st.EnrolledAt.Local().Format(time.RFC1123))
	fmt.Fprintf(&b, "Status:      %s (last checked %s)\n", st.Status, ago(st.LastCheckedAt))
	if rt != nil {
		reach := "unreachable"
		if rt.IssuerReachable {
			reach = "reachable"
		}
		fmt.Fprintf(&b, "Daemon:      omni identity %s; token renewed %s", reach, ago(rt.LastRenewedAt))
		if !rt.TokenExpiresAt.IsZero() {
			fmt.Fprintf(&b, ", expires %s", rt.TokenExpiresAt.Local().Format(time.Kitchen))
		}
		b.WriteString("\n")
		if rt.LastError != "" {
			fmt.Fprintf(&b, "Last error:  %s\n", rt.LastError)
		}
	}
	return b.String()
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t).Round(time.Second)
	if d < time.Minute {
		return "just now"
	}
	return d.Truncate(time.Minute).String() + " ago"
}
