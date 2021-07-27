package sign

import (
	io "io"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
)

// messageHash is a wrapper around bytes to provide some domain separation
type messageHash []byte

// WriteTo makes messageHash implement the io.WriterTo interface.
func (m messageHash) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(m)
	return int64(n), err
}

// Domain implements WriterToWithDomain, and separates this type within hash.Hash.
func (messageHash) Domain() string {
	return "messageHash"
}

// Signature represents the result of a Schnorr signature.
//
// This signature claims to satisfy:
//
//    z * G = R + H(R, Y, m) * Y
//
// for a public key Y.
type Signature struct {
	// R is the commitment point.
	R *curve.Point
	// z is the response scalar.
	z *curve.Scalar
}

// Verify checks if a signature equation actually holds.
//
// Note that m is the hash of a message, and not the message itself.
func (sig Signature) Verify(public *curve.Point, m []byte) bool {
	challengeHash := hash.New()
	challengeHash.WriteAny(sig.R, public, messageHash(m))
	challenge := sample.Scalar(challengeHash)

	expected := curve.NewIdentityPoint().ScalarMult(challenge, public)
	expected.Add(expected, sig.R)

	actual := curve.NewIdentityPoint().ScalarBaseMult(sig.z)

	return expected.Equal(actual)
}
