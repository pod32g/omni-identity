package enrollment

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Enrollment is an in-progress ceremony (device grant method) split into a
// start and a wait step so both the CLI and the local GUI can drive it: the
// key exists and the RFC 8628 grant has been started; the user must approve
// the code at Omni; Wait polls, registers the key, and persists the state.
type Enrollment struct {
	agent  *Agent
	cfg    Config
	client *Client
	key    Signer
	meta   Metadata
	da     *DeviceAuthorization
	start  time.Time
}

// Verification details to show the user.
func (e *Enrollment) VerificationURI() string         { return e.da.VerificationURI }
func (e *Enrollment) VerificationURIComplete() string { return e.da.VerificationURIComplete }
func (e *Enrollment) UserCode() string                { return e.da.UserCode }
func (e *Enrollment) ExpiresAt() time.Time {
	return e.start.Add(time.Duration(e.da.ExpiresIn) * time.Second)
}
func (e *Enrollment) Fingerprint() string  { return e.key.Fingerprint() }
func (e *Enrollment) KeyAlgorithm() string { return e.key.Algorithm() }
func (e *Enrollment) Device() Metadata     { return e.meta }

// BeginEnrollment generates the device key and starts the device grant.
// On any later failure the caller must call Abort so the key is removed.
func (a *Agent) BeginEnrollment(ctx context.Context, cfg Config) (*Enrollment, error) {
	if _, err := LoadState(a.StateDir); err == nil {
		return nil, errors.New("this machine is already enrolled (unenroll first)")
	}
	key, err := GenerateKeyWith(a.StateDir, cfg.KeyBackend, cfg.TPMDevice, false)
	if err != nil {
		return nil, err
	}
	client, err := NewClient(Options{Issuer: cfg.Issuer, ClientID: cfg.ClientID, Signer: key,
		AllowInsecureHTTP: cfg.AllowInsecureHTTP, CAFile: cfg.CAFile, Transport: a.Transport})
	if err != nil {
		_ = RemoveState(a.StateDir)
		return nil, err
	}
	meta := LocalMetadata(cfg.Name)
	da, err := client.StartDeviceAuthorization(ctx, ScopeEnroll,
		map[string]string{"device_name": meta.Name, "device_platform": meta.Platform}, "")
	if err != nil {
		_ = RemoveState(a.StateDir)
		return nil, fmt.Errorf("start enrollment: %w", err)
	}
	return &Enrollment{agent: a, cfg: cfg, client: client, key: key, meta: meta, da: da, start: time.Now()}, nil
}

// Wait polls until the user approves, registers the key, and saves the
// state. On failure the generated key is removed so a retry starts clean.
func (e *Enrollment) Wait(ctx context.Context, onWait func()) (*State, error) {
	tok, err := e.client.WaitForDeviceCode(ctx, e.da, "", onWait)
	if err != nil {
		e.Abort()
		return nil, fmt.Errorf("enrollment was not approved: %w", err)
	}
	return e.complete(ctx, tok)
}

// complete registers the key with the DPoP-bound token and persists state.
func (e *Enrollment) complete(ctx context.Context, tok *TokenResponse) (*State, error) {
	a, cfg, client := e.agent, e.cfg, e.client
	dev, err := client.Enroll(ctx, tok.AccessToken, e.meta)
	if err != nil {
		e.Abort()
		return nil, fmt.Errorf("register device: %w", err)
	}
	enrolledAt, _ := time.Parse(time.RFC3339, dev.EnrolledAt)
	st := &State{
		Issuer: client.Issuer, ClientID: client.ClientID, DeviceID: dev.ID, Fingerprint: dev.Fingerprint,
		Name: dev.Name, OwnerSub: dev.OwnerSub, OwnerUsername: dev.OwnerUsername, EnrolledAt: enrolledAt,
		Status: dev.Status, LastCheckedAt: time.Now().UTC(),
		AllowInsecureHTTP: cfg.AllowInsecureHTTP, CAFile: cfg.CAFile,
		KeyBackend: orDefault(cfg.KeyBackend, KeyBackendFile), TPMDevice: cfg.TPMDevice,
	}
	if err := SaveState(a.StateDir, st); err != nil {
		return nil, err
	}
	if a.Accounts != nil {
		if err := a.EnsureOwnerAccount(st, a.Accounts); err != nil && a.logf != nil {
			a.logf("prepare owner identity: %v", err)
		}
	}
	return st, nil
}

// Abort discards the generated key and state.
func (e *Enrollment) Abort() { _ = RemoveState(e.agent.StateDir) }
