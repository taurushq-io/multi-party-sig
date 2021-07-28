package taproot

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
)

// TaggedHash addes some domain separation to SHA-256.
//
// This is the hash_tag function mentioned in BIP-340.
//
// See: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#specification
func TaggedHash(tag string, datas ...[]byte) []byte {
	tagHash := sha256.New()
	tagHash.Write([]byte(tag))

	tagSum := tagHash.Sum(nil)

	h := sha256.New()
	h.Write(tagSum)
	h.Write(tagSum)
	for _, data := range datas {
		h.Write(data)
	}
	return h.Sum(nil)
}

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

type Signature []byte

// signatureCounter is an atomic counter used to add some fault
// resistance in case we don't use a source of randomness for Sign
var signatureCounter uint64

func (s SecretKey) Sign(rand io.Reader, m []byte) (Signature, error) {

	d, ok := curve.NewScalar().SetBytes(s)
	if !ok || d.IsZero() {
		return nil, fmt.Errorf("invalid secret key")
	}

	P := curve.NewIdentityPoint().ScalarBaseMult(d)
	PBytes := P.XBytes()[:]

	if !P.HasEvenY() {
		d.Negate(d)
	}

	a := make([]byte, 32)
	k := curve.NewScalar()
	for k.IsZero() {
		// Either read new random bytes into a, or increment a global counter.
		//
		// Either way, the probability of us not finding a valid nonce
		// is negligeable.
		if rand != nil {
			if _, err := io.ReadFull(rand, a); err != nil {
				return nil, err
			}
		} else {
			// Need to use atomics, because of potential multi-threading
			ctr := atomic.AddUint64(&signatureCounter, 1)
			binary.BigEndian.PutUint64(a, ctr)
		}

		t := d.Bytes()
		aHash := TaggedHash("BIP0340/aux", a)
		for i := 0; i < 32; i++ {
			t[i] ^= aHash[i]
		}

		randHash := TaggedHash("BIP0340/nonce", t[:], PBytes, m)

		k, _ = curve.NewScalar().SetBytes(randHash)
	}

	R := curve.NewIdentityPoint().ScalarBaseMult(k)

	if !R.HasEvenY() {
		k.Negate(k)
	}

	RBytes := R.XBytes()[:]

	eHash := TaggedHash("BIP0340/challenge", RBytes, PBytes, m)
	e, _ := curve.NewScalar().SetBytes(eHash)

	z := e.MultiplyAdd(e, d, k)
	zBytes := z.Bytes()

	sig := make([]byte, 0, 64)
	sig = append(sig, RBytes...)
	sig = append(sig, zBytes[:]...)

	return Signature(sig), nil
}

func (pk PublicKey) Verify(sig Signature, m []byte) bool {
	P, err := curve.LiftX(pk)
	if err != nil {
		return false
	}
	s, overflow := curve.NewScalar().SetBytes(sig[32:])
	if overflow {
		return false
	}
	eHash := TaggedHash("BIP0340/challenge", sig[:32], P.XBytes()[:], m)
	e, _ := curve.NewScalar().SetBytes(eHash)

	R := curve.NewIdentityPoint().ScalarBaseMult(s)
	R.Subtract(R, P.ScalarMult(e, P))
	if R.IsIdentity() {
		return false
	}
	if !R.HasEvenY() {
		return false
	}
	return bytes.Equal(R.XBytes()[:], sig[:32])
}
