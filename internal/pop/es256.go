package pop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
)

// ES256 for opaque signers. golang-jwt's built-in ES256 method only accepts
// *ecdsa.PrivateKey; a hardware-backed key (TPM 2.0, Secure Enclave) is a
// crypto.Signer whose private half never exists in memory. This method
// registers under the same "ES256" name, delegates verification and software
// keys to the standard implementation, and signs through crypto.Signer
// otherwise (DER signature → fixed-size R||S as JWS requires).
type es256Method struct{ std *jwt.SigningMethodECDSA }

func init() {
	m := &es256Method{std: jwt.SigningMethodES256}
	jwt.RegisterSigningMethod(m.Alg(), func() jwt.SigningMethod { return m })
}

func (m *es256Method) Alg() string { return m.std.Alg() }

func (m *es256Method) Verify(signingString string, sig []byte, key any) error {
	return m.std.Verify(signingString, sig, key)
}

func (m *es256Method) Sign(signingString string, key any) ([]byte, error) {
	if k, ok := key.(*ecdsa.PrivateKey); ok {
		return m.std.Sign(signingString, k)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, jwt.ErrInvalidKeyType
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("es256: signer is not a P-256 key")
	}
	digest := sha256.Sum256([]byte(signingString))
	der, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &rs); err != nil {
		return nil, errors.New("es256: signer returned a non-DER signature")
	}
	out := make([]byte, 64)
	rs.R.FillBytes(out[:32])
	rs.S.FillBytes(out[32:])
	return out, nil
}
