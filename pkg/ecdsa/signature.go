package eddsa

import (
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers/scalar"
)

const MessageLengthSig = 32 + 32

var ErrInvalidMessage = errors.New("invalid message")

type Signature struct {
	R edwards25519.Point
	S edwards25519.Scalar
}

func NewSignature(message []byte, secretKey *PrivateKey, publicKey *PublicKey) *Signature {
	var sig Signature
	var r edwards25519.Scalar
	scalar.SetScalarRandom(&r)
	sig.R.ScalarBaseMult(&r)
	c := ComputeChallenge(message, publicKey.Point(), &sig.R)
	sig.S.Multiply(secretKey.Scalar(), c)
	sig.S.Add(&sig.S, &r)
	return &sig
}

func (s *Signature) Verify(message []byte, publicKey *PublicKey) bool {
	var RPrime edwards25519.Point

	k := ComputeChallenge(message, publicKey.Point(), &s.R)
	k.Negate(k)
	// RPrime = [-l]A + [s]B
	RPrime.VarTimeDoubleScalarBaseMult(k, publicKey.Point(), &s.S)

	return RPrime.Equal(&s.R) == 1
}

//
// FROSTMarshaller
//

func (s *Signature) MarshalBinary() ([]byte, error) {
	var buf [MessageLengthSig]byte
	return s.BytesAppend(buf[:0])
}

func (s *Signature) UnmarshalBinary(data []byte) error {
	var err error
	if len(data) != MessageLengthSig {
		return fmt.Errorf("sig: %w", ErrInvalidMessage)
	}
	_, err = s.R.SetBytes(data[:32])
	if err != nil {
		return fmt.Errorf("sig.Ri: %w", err)
	}
	_, err = s.S.SetCanonicalBytes(data[32:])
	if err != nil {
		return fmt.Errorf("sig.S: %w", err)
	}

	return nil
}

func (s *Signature) BytesAppend(existing []byte) ([]byte, error) {
	existing = append(existing, s.R.Bytes()...)
	existing = append(existing, s.S.Bytes()...)
	return existing, nil
}

func (s *Signature) Size() int {
	return MessageLengthSig
}
