package taproot

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

// TaggedHash addes some domain separation to SHA-256.
//
// This is the hash_tag function mentioned in BIP-340.
//
// See: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#specification
func TaggedHash(tag string, datas ...[]byte) []byte {
	tagSum := sha256.Sum256([]byte(tag))

	h := sha256.New()
	h.Write(tagSum[:])
	h.Write(tagSum[:])
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

// SignatureLen is the number of bytes in a Signature.
const SignatureLen = 64

// Signature represents a signature according to BIP-340.
//
// This should exactly SignatureLen = 64 bytes long.
//
// This can only be produced using a secret key, but anyone with a public key
// can verify the integrity of the signature.
type Signature []byte

// signatureCounter is an atomic counter used to add some fault
// resistance in case we don't use a source of randomness for Sign
var signatureCounter uint64

// Sign uses a secret key to create a new signature.
//
// Note that m should be the hash of a message, and not the actual message.
//
// This accepts a source of randomness, but nil can be passed to use entirely
// deterministic signatures. Adding randomness hardens the implementation against
// fault attacks, but isn't strictly necessary for security.
//
// Without randomness, an atomic counter is used to also hedge against attacks.
//
// Errors will be returned if the source of randomness produces an error,
// or if the secret key is invalid.
func (sk SecretKey) Sign(rand io.Reader, m []byte) (Signature, error) {
	// See: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#default-signing
	d, ok := curve.NewScalar().SetBytes(sk)
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

	z := curve.NewScalar().MultiplyAdd(e, d, k)
	zBytes := z.Bytes()

	sig := make([]byte, 0, SignatureLen)
	sig = append(sig, RBytes...)
	sig = append(sig, zBytes[:]...)

	return Signature(sig), nil
}

// Verify checks the integrity of a signature, using a public key.
//
// Note that m is the hash of a message, and not the message itself.
func (pk PublicKey) Verify(sig Signature, m []byte) bool {
	// See: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#verification
	if len(sig) != SignatureLen {
		return false
	}

	P, err := curve.LiftX(pk)
	if err != nil {
		return false
	}
	s, ok := curve.NewScalar().SetBytes(sig[32:])
	if !ok {
		return false
	}
	eHash := TaggedHash("BIP0340/challenge", sig[:32], pk, m)
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
