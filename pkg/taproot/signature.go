package taproot

import (
	"fmt"
	"io"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
)

// SecretKeyLength is the number of bytes in a SecretKey.
const SecretKeyLength = 32

// SecretKey represents a secret key for BIP-340 signatures.
//
// This is simply an array of 32 bytes.
type SecretKey []byte

// PublicKey represents a public key for BIP-340 signatures.
//
// This key allows verifying signatures produced with the corresponding secret key.
//
// This is simply an array of 32 bytes.
type PublicKey []byte

// Public calculates the public key corresponding to a given secret key.
//
// This will return an error if the secret key is invalid.
//
// See: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#public-key-generation
func (s SecretKey) Public() (PublicKey, error) {
	scalar, ok := curve.NewScalar().SetBytes(s)
	if !ok || scalar.IsZero() {
		return nil, fmt.Errorf("invalid secret key")
	}
	point := curve.NewIdentityPoint().ScalarBaseMult(scalar)
	return PublicKey(point.XBytes()[:]), nil
}

// GenKey generates a new key-pair, from a source of randomness.
//
// Errors returned by this function will only come from the reader. If you know
// that the reader will never return errors, you can rest assured that this
// function won't either.
func GenKey(rand io.Reader) (SecretKey, PublicKey, error) {
	for {
		secret := SecretKey(make([]byte, SecretKeyLength))
		if _, err := io.ReadFull(rand, secret); err != nil {
			return nil, nil, err
		}
		if public, err := secret.Public(); err == nil {
			return secret, public, nil
		}
	}
}
