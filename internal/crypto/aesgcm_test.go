package crypto

import "testing"

func TestEncryptDecryptRoundTrip(t *testing.T) {
	keyB64, err := GenerateKeyB64()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := NewEncryptorFromB64(keyB64)
	if err != nil {
		t.Fatal(err)
	}

	plain := "JBSWY3DPEHPK3PXP" // a TOTP secret
	ct, err := enc.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if ct == plain {
		t.Fatal("ciphertext equals plaintext")
	}
	got, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Errorf("decrypt = %q, want %q", got, plain)
	}

	// A different key must not decrypt.
	otherB64, _ := GenerateKeyB64()
	other, _ := NewEncryptorFromB64(otherB64)
	if _, err := other.Decrypt(ct); err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}

func TestEncryptIsNondeterministic(t *testing.T) {
	keyB64, _ := GenerateKeyB64()
	enc, _ := NewEncryptorFromB64(keyB64)
	a, _ := enc.Encrypt("x")
	b, _ := enc.Encrypt("x")
	if a == b {
		t.Error("expected unique nonces to yield different ciphertexts")
	}
}

func TestNewEncryptorRejectsBadKey(t *testing.T) {
	if _, err := NewEncryptor([]byte("short")); err == nil {
		t.Error("expected error for short key")
	}
}
