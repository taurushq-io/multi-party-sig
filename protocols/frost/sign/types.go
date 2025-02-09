package sign

import (
	"errors"
	"io"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

// messageHash is a wrapper around bytes to provide some domain separation.
type messageHash []byte

// WriteTo makes messageHash implement the io.WriterTo interface.
func (m messageHash) WriteTo(w io.Writer) (int64, error) {
	if m == nil {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := w.Write(m)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (messageHash) Domain() string {
	return "messageHash"
}

// Signature represents the result of a Schnorr signature.
//
// This signature claims to satisfy:
//
//	z * G = R + H(R, Y, m) * Y
//
// for a public key Y.
type Signature struct {
	Group curve.Curve
	// R is the commitment point.
	R curve.Point
	// z is the response scalar.
	z curve.Scalar
}

type signatureMarshal struct {
	// R is the commitment point.
	R curve.Point
	// z is the response scalar.
	Z curve.Scalar
}

// Verify checks if a signature equation actually holds.
//
// Note that m is the hash of a message, and not the message itself.
func (sig Signature) Verify(public curve.Point, m []byte) bool {
	group := public.Curve()

	challengeHash := hash.New()
	_ = challengeHash.WriteAny(sig.R, public, messageHash(m))
	challenge := sample.Scalar(challengeHash.Digest(), group)

	expected := challenge.Act(public)
	expected = expected.Add(sig.R)

	actual := sig.z.ActOnBase()

	return expected.Equal(actual)
}

func (sig *Signature) MarshalBinary() ([]byte, error) {
	return cbor.Marshal(&signatureMarshal{
		R: sig.R,
		Z: sig.z,
	})
}

func (sig *Signature) UnmarshalBinary(data []byte) error {
	if sig.Group == nil {
		return errors.New("can't unmarshal frost signature with no group")
	}
	sigMarshal := &signatureMarshal{
		R: sig.Group.NewPoint(),
		Z: sig.Group.NewScalar(),
	}
	if err := cbor.Unmarshal(data, sigMarshal); err != nil {
		return err
	}
	sig.R, sig.z = sigMarshal.R, sigMarshal.Z
	return nil
}
