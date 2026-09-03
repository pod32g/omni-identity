package enrollment

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pod32g/omni-identity/internal/pop"
)

// Set OMNI_TEST_TPM to a TPM (tcp://127.0.0.1:2321 for a swtpm started with
// --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --tpm2 --flags
// not-need-init,startup-clear) to run this.
func TestTPMKeyLifecycle(t *testing.T) {
	dev := os.Getenv("OMNI_TEST_TPM")
	if dev == "" {
		t.Skip("set OMNI_TEST_TPM to a TPM device or tcp://host:port to run")
	}
	dir := t.TempDir()
	k, err := GenerateKeyWith(dir, KeyBackendTPM, dev, false)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if k.Algorithm() != pop.AlgES256 || k.Fingerprint() == "" {
		t.Fatalf("key = alg %s fp %q", k.Algorithm(), k.Fingerprint())
	}
	if _, err := os.Stat(filepath.Join(dir, tpmBlobFile)); err != nil {
		t.Fatal("blobs not persisted")
	}
	if _, err := os.Stat(filepath.Join(dir, keyFileName)); err == nil {
		t.Fatal("a software key must not exist alongside the TPM key")
	}
	// Blobs contain no usable private key: they are SRK-wrapped.
	raw, _ := os.ReadFile(filepath.Join(dir, tpmBlobFile))
	if len(raw) == 0 {
		t.Fatal("empty blob file")
	}

	// Sign and verify with the public half.
	digest := sha256.Sum256([]byte("hello"))
	der, err := k.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ecdsa.VerifyASN1(k.Public().(*ecdsa.PublicKey), digest[:], der) {
		t.Fatal("signature does not verify")
	}
	// The whole JWT path (DPoP proof + RFC 7523 assertion) through the TPM.
	now := time.Now()
	assertion, err := pop.NewAssertion(k, k.Fingerprint(), "dev", "https://id", now, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pop.VerifyAssertion(assertion, pop.AssertionOptions{Key: k.Public(), Alg: pop.AlgES256, Audience: "https://id", Now: now}); err != nil {
		t.Fatalf("assertion: %v", err)
	}
	proof, err := pop.NewProof(k, "POST", "https://id/t", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := pop.VerifyProof(proof, pop.ProofOptions{Now: now, HTM: "POST", HTU: "https://id/t"}); err != nil || p.JKT != k.Fingerprint() {
		t.Fatalf("proof: %v", err)
	}
	// Reload from disk: same key, loads in the TPM.
	k2, err := LoadKey(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if k2.Fingerprint() != k.Fingerprint() {
		t.Fatal("reloaded key differs")
	}
	// Rotation-style: a second key is a different key.
	k3, err := GenerateTPMKey(dev)
	if err != nil {
		t.Fatal(err)
	}
	if k3.Fingerprint() == k.Fingerprint() {
		t.Fatal("two TPM keys share a fingerprint")
	}
	if err := CommitTPMKey(dir, k3); err != nil {
		t.Fatal(err)
	}
	if k4, _ := LoadKey(dir); k4.Fingerprint() != k3.Fingerprint() {
		t.Fatal("commit did not replace the key")
	}
	// Corrupt blobs must not load.
	_ = os.WriteFile(filepath.Join(dir, tpmBlobFile), []byte(`{"device":"`+dev+`","public":"AAAA","private":"AAAA"}`), 0o600)
	if _, err := LoadKey(dir); err == nil {
		t.Fatal("corrupt blobs loaded")
	}
}
