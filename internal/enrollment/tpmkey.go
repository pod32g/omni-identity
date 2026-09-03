package enrollment

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/tcp"
	"github.com/pod32g/omni-identity/internal/pop"
)

// TPM 2.0-backed device key (docs/DEVICE-IDENTITY-ARCHITECTURE.md §4). The
// signing key is an ECDSA P-256 key created by the TPM under the owner
// hierarchy's storage root key, with FixedTPM and SensitiveDataOrigin set:
// the private half is generated inside the TPM and can never leave it. What
// the daemon stores on disk is the TPM's wrapped private blob plus the public
// area, which only this TPM can load — a copied filesystem is inert (threat
// model §4.9). Signatures go through TPM2_Sign; the key surfaces to the rest
// of the agent as a crypto.Signer with alg ES256, which Omni already accepts.
//
// Device paths: "/dev/tpmrm0" (Linux resource manager, default) or
// "tcp://host:port" for a software TPM speaking the MS simulator protocol
// (swtpm socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322).

// DefaultTPMDevice is the Linux TPM resource manager.
const DefaultTPMDevice = "/dev/tpmrm0"

const tpmBlobFile = "device.tpm.json"

// tpmBlobs is the on-disk form (0600 root): wrapped by the SRK, useless
// without the same TPM.
type tpmBlobs struct {
	Device  string `json:"device"`
	Public  string `json:"public"`  // base64 TPM2B_PUBLIC
	Private string `json:"private"` // base64 TPM2B_PRIVATE (SRK-wrapped)
}

type tpmKey struct {
	blobs   tpmBlobs
	public  tpm2.TPM2BPublic
	private tpm2.TPM2BPrivate
	pub     *ecdsa.PublicKey
	jwk     *pop.JWK
	fp      string
	mu      sync.Mutex // one TPM conversation at a time
}

func (k *tpmKey) Algorithm() string        { return pop.AlgES256 }
func (k *tpmKey) JWK() *pop.JWK            { return k.jwk }
func (k *tpmKey) Fingerprint() string      { return k.fp }
func (k *tpmKey) Public() crypto.PublicKey { return k.pub }

// signingTemplate is the P-256 ECDSA signing key template.
func tpmSigningTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			CurveID: tpm2.TPMECCNistP256,
			KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
	}
}

// openTPM connects to a TPM by path.
func openTPM(device string) (transport.TPMCloser, error) {
	if device == "" {
		device = DefaultTPMDevice
	}
	if addr, ok := strings.CutPrefix(device, "tcp://"); ok {
		// Platform port = command port + 1 by convention; commands only.
		host, port, ok := strings.Cut(addr, ":")
		if !ok {
			return nil, fmt.Errorf("tpm: tcp device must be tcp://host:port, got %q", device)
		}
		var p int
		if _, err := fmt.Sscanf(port, "%d", &p); err != nil {
			return nil, fmt.Errorf("tpm: bad port in %q", device)
		}
		return tcp.Open(tcp.Config{CommandAddress: fmt.Sprintf("%s:%d", host, p), PlatformAddress: fmt.Sprintf("%s:%d", host, p+1)})
	}
	return openDeviceTPM(device)
}

// withSRK runs fn with the ECC storage root key loaded, then flushes it. The
// SRK is recreated deterministically from the owner seed each time, so no
// persistent handle is needed.
func withSRK(tpm transport.TPM, fn func(srk tpm2.NamedHandle) error) error {
	var rsp *tpm2.CreatePrimaryResponse
	if err := retryTPM(func() (e error) {
		rsp, e = tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}.Execute(tpm)
		return e
	}); err != nil {
		return fmt.Errorf("tpm: create SRK: %w", err)
	}
	defer func() { _, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(tpm) }()
	return fn(tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name})
}

// GenerateTPMKey creates a new signing key in the TPM and returns it without
// persisting; CommitTPMKey writes it. (Rotation registers the new key with
// Omni before committing it locally.)
func GenerateTPMKey(device string) (Signer, error) {
	tpm, err := openTPM(device)
	if err != nil {
		return nil, err
	}
	defer tpm.Close()
	var k *tpmKey
	err = withSRK(tpm, func(srk tpm2.NamedHandle) error {
		var rsp *tpm2.CreateResponse
		if err := retryTPM(func() (e error) {
			rsp, e = tpm2.Create{ParentHandle: srk, InPublic: tpm2.New2B(tpmSigningTemplate())}.Execute(tpm)
			return e
		}); err != nil {
			return fmt.Errorf("tpm: create key: %w", err)
		}
		k, err = newTPMKey(device, rsp.OutPublic, rsp.OutPrivate)
		return err
	})
	if err != nil {
		return nil, err
	}
	return k, nil
}

func newTPMKey(device string, public tpm2.TPM2BPublic, private tpm2.TPM2BPrivate) (*tpmKey, error) {
	area, err := public.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpm: public area: %w", err)
	}
	point, err := area.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("tpm: not an ECC key: %w", err)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(point.X.Buffer), Y: new(big.Int).SetBytes(point.Y.Buffer)}
	jwk, err := pop.FromPublicKey(pub)
	if err != nil {
		return nil, err
	}
	fp, err := jwk.Thumbprint()
	if err != nil {
		return nil, err
	}
	if device == "" {
		device = DefaultTPMDevice
	}
	return &tpmKey{
		blobs: tpmBlobs{Device: device,
			Public:  base64.StdEncoding.EncodeToString(tpm2.Marshal(&public)),
			Private: base64.StdEncoding.EncodeToString(tpm2.Marshal(&private))},
		public: public, private: private, pub: pub, jwk: jwk, fp: fp,
	}, nil
}

// CommitTPMKey persists a TPM key's blobs into dir (0600) and removes any
// software key so LoadKey picks the TPM one.
func CommitTPMKey(dir string, s Signer) error {
	k, ok := s.(*tpmKey)
	if !ok {
		return errors.New("tpm: not a TPM key")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(k.blobs, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, tpmBlobFile)
	if err := os.WriteFile(path+".tmp", raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(dir, keyFileName))
	return nil
}

// LoadTPMKey reads the blobs from dir and checks the TPM can still load them.
func LoadTPMKey(dir string) (Signer, error) {
	raw, err := os.ReadFile(filepath.Join(dir, tpmBlobFile))
	if err != nil {
		return nil, err
	}
	var b tpmBlobs
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("tpm: blob file: %w", err)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(b.Public)
	if err != nil {
		return nil, err
	}
	privBytes, err := base64.StdEncoding.DecodeString(b.Private)
	if err != nil {
		return nil, err
	}
	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubBytes)
	if err != nil {
		return nil, fmt.Errorf("tpm: public blob: %w", err)
	}
	private, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privBytes)
	if err != nil {
		return nil, fmt.Errorf("tpm: private blob: %w", err)
	}
	k, err := newTPMKey(b.Device, *public, *private)
	if err != nil {
		return nil, err
	}
	// Prove the TPM still accepts the blobs (wrong TPM → load fails).
	if err := k.withLoaded(func(transport.TPM, tpm2.NamedHandle) error { return nil }); err != nil {
		return nil, err
	}
	return k, nil
}

// retryTPM retries a TPM command a few times on TPM_RC_RETRY, which the
// resource manager and the reference simulator can return under load.
func retryTPM(fn func() error) error {
	var err error
	for i := 0; i < 8; i++ {
		if err = fn(); err == nil || !strings.Contains(err.Error(), "TPM_RC_RETRY") {
			return err
		}
		time.Sleep(time.Duration(i+1) * 20 * time.Millisecond)
	}
	return err
}

// withLoaded opens the TPM, loads the key under the SRK, runs fn, flushes.
func (k *tpmKey) withLoaded(fn func(tpm transport.TPM, key tpm2.NamedHandle) error) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	tpm, err := openTPM(k.blobs.Device)
	if err != nil {
		return err
	}
	defer tpm.Close()
	return withSRK(tpm, func(srk tpm2.NamedHandle) error {
		var rsp *tpm2.LoadResponse
		if err := retryTPM(func() (e error) {
			rsp, e = tpm2.Load{ParentHandle: srk, InPrivate: k.private, InPublic: k.public}.Execute(tpm)
			return e
		}); err != nil {
			return fmt.Errorf("tpm: load key (wrong TPM or corrupt blobs?): %w", err)
		}
		defer func() { _, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(tpm) }()
		return fn(tpm, tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name})
	})
}

// Sign implements crypto.Signer: digest must be SHA-256; returns DER.
func (k *tpmKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, errors.New("tpm: only SHA-256 digests are supported")
	}
	var der []byte
	err := k.withLoaded(func(tpm transport.TPM, key tpm2.NamedHandle) error {
		var rsp *tpm2.SignResponse
		if err := retryTPM(func() (e error) {
			rsp, e = tpm2.Sign{
				KeyHandle: key,
				Digest:    tpm2.TPM2BDigest{Buffer: digest},
				InScheme: tpm2.TPMTSigScheme{
					Scheme:  tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
				},
				Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
			}.Execute(tpm)
			return e
		}); err != nil {
			return fmt.Errorf("tpm: sign: %w", err)
		}
		sig, err := rsp.Signature.Signature.ECDSA()
		if err != nil {
			return fmt.Errorf("tpm: signature: %w", err)
		}
		der, err = asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig.SignatureR.Buffer), new(big.Int).SetBytes(sig.SignatureS.Buffer)})
		return err
	})
	if err != nil {
		return nil, err
	}
	return der, nil
}
