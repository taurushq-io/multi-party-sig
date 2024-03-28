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
	scalar := new(curve.Secp256k1Scalar)
	if err := scalar.UnmarshalBinary(s); err != nil || scalar.IsZero() {
		return nil, fmt.Errorf("invalid secret key")
	}
	point := scalar.ActOnBase().(*curve.Secp256k1Point)
	return PublicKey(point.XBytes()), nil
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

// Serialized adaptor signatures have an extra byte for the R point's Y coordinate parity
const AdaptorSignatureLen = SignatureLen + 1

// Signature represents a signature according to BIP-340.
//
// This should exactly SignatureLen = 64 bytes long.
//
// This can only be produced using a secret key, but anyone with a public key
// can verify the integrity of the signature.
type Signature []byte

type AdaptorSignature struct {
	R curve.Secp256k1Point
	z curve.Secp256k1Scalar
}

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
	d := new(curve.Secp256k1Scalar)
	if err := d.UnmarshalBinary(sk); err != nil || d.IsZero() {
		return nil, fmt.Errorf("invalid secret key")
	}

	P := d.ActOnBase().(*curve.Secp256k1Point)
	PBytes := P.XBytes()

	if !P.HasEvenY() {
		d.Negate()
	}

	a := make([]byte, 32)
	k := new(curve.Secp256k1Scalar)
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

		t, _ := d.MarshalBinary()
		aHash := TaggedHash("BIP0340/aux", a)
		for i := 0; i < 32; i++ {
			t[i] ^= aHash[i]
		}

		randHash := TaggedHash("BIP0340/nonce", t[:], PBytes, m)

		_ = k.UnmarshalBinary(randHash)
		if k.IsZero() {
			return nil, fmt.Errorf("invalid nonce")
		}
	}

	R := k.ActOnBase().(*curve.Secp256k1Point)

	if !R.HasEvenY() {
		k.Negate()
	}

	RBytes := R.XBytes()[:]

	eHash := TaggedHash("BIP0340/challenge", RBytes, PBytes, m)
	e := new(curve.Secp256k1Scalar)
	_ = e.UnmarshalBinary(eHash)

	z := e.Mul(d).Add(k)
	zBytes, _ := z.MarshalBinary()

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

	P, err := curve.Secp256k1{}.LiftX(pk)
	if err != nil {
		return false
	}
	s := new(curve.Secp256k1Scalar)
	if err := s.UnmarshalBinary(sig[32:]); err != nil {
		return false
	}
	eHash := TaggedHash("BIP0340/challenge", sig[:32], pk, m)
	e := new(curve.Secp256k1Scalar)
	_ = e.UnmarshalBinary(eHash)

	R := s.ActOnBase()
	check2 := R.Sub(e.Act(P))
	check := check2.(*curve.Secp256k1Point)
	if check.IsIdentity() {
		return false
	}
	if !check.HasEvenY() {
		return false
	}
	return bytes.Equal(check.XBytes(), sig[:32])
}

func NewAdaptorSignature(R curve.Secp256k1Point, z curve.Secp256k1Scalar) AdaptorSignature {
	return AdaptorSignature{
		R: R,
		z: z,
	}
}

func DeserializeAdaptorSignature(b []byte) (AdaptorSignature, error) {
	if len(b) != AdaptorSignatureLen {
		return AdaptorSignature{},
			fmt.Errorf("invalid adaptor signature length: expected %v, got %v", AdaptorSignatureLen, len(b))
	}
	if !(b[0] == 0x02 || b[0] == 0x03) {
		return AdaptorSignature{},
			fmt.Errorf("invalid R point: expected parity byte of 0x02 or 0x03, got %v", b[0])
	}
	var R curve.Secp256k1Point
	if err := R.UnmarshalBinary(b[:33]); err != nil {
		return AdaptorSignature{}, err
	}
	var z curve.Secp256k1Scalar
	if err := z.UnmarshalBinary(b[33:]); err != nil {
		return AdaptorSignature{}, err
	}
	return NewAdaptorSignature(R, z), nil
}

func (pk PublicKey) VerifyAdaptor(sig AdaptorSignature, T curve.Secp256k1Point, m []byte) bool {
	P, err := curve.Secp256k1{}.LiftX(pk)
	if err != nil {
		return false
	}

	RplusT := sig.R.Add(&T).(*curve.Secp256k1Point)
	RplusTbytes := RplusT.XBytes()

	eHash := TaggedHash("BIP0340/challenge", RplusTbytes, pk, m)
	e := new(curve.Secp256k1Scalar)
	_ = e.UnmarshalBinary(eHash)

	R := sig.z.ActOnBase()
	check2 := R.Sub(e.Act(P))
	check := check2.(*curve.Secp256k1Point)
	if check.IsIdentity() {
		return false
	}

	if RplusT.HasEvenY() != (check.HasEvenY() == sig.R.HasEvenY()) {
		// failed parity check
		return false
	}

	return bytes.Equal(check.XBytes(), sig.R.XBytes())
}

func (sig AdaptorSignature) Serialize() (out [65]byte) {
	out[0] = 0x03
	if sig.R.HasEvenY() {
		out[0] = 0x02
	}
	copy(out[1:], sig.R.XBytes())
	zBytes, _ := sig.z.MarshalBinary()
	copy(out[33:], zBytes[:])
	return out
}

func (sig AdaptorSignature) Complete(t curve.Secp256k1Scalar) (Signature, error) {
	// math from https://github.com/t-bast/lightning-docs/blob/master/schnorr.md#adaptor-signatures
	// Complete:
	//  s' = s + t
	//  R' = R + T
	//  (s', R') -> valid schnorr signature

	T := t.ActOnBase().(*curve.Secp256k1Point)

	RPrime := sig.R.Add(T).(*curve.Secp256k1Point)
	if !RPrime.HasEvenY() {
		t.Negate()
	}
	sPrime := sig.z.Add(&t)

	RPrimeBytes := RPrime.XBytes()
	sPrimeBytes, _ := sPrime.MarshalBinary()

	var outSig [64]byte
	copy(outSig[:32], RPrimeBytes[:])
	copy(outSig[32:], sPrimeBytes[:])
	return outSig[:], nil
}
