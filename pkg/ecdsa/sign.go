package eddsa

import (
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// Compute the SHA 512 of the message
func ComputeMessageHash(message []byte) []byte {
	var out [64]byte
	h := sha512.New()
	h.Write(message)
	h.Sum(out[:0])
	return out[:]
}

// ComputeChallenge computes the value H(Ri, A, M), and assumes nothing about whether M is hashed.
// It returns a Scalar.
func ComputeChallenge(message []byte, groupKey, R *edwards25519.Point) *edwards25519.Scalar {
	var s edwards25519.Scalar
	return SetChallenge(&s, message, groupKey, R)
}

// SetChallenge set s to the edwards25519.Scalar value of H(Ri, A, M).
func SetChallenge(s *edwards25519.Scalar, message []byte, groupKey, R *edwards25519.Point) *edwards25519.Scalar {
	//var kHash [64]byte

	h := sha512.New()
	h.Write(R.Bytes())
	h.Write(groupKey.Bytes())
	h.Write(message)
	//h.Sum(kHash[:0])
	s.SetUniformBytes(h.Sum(nil))
	//s.SetUniformBytes(kHash[:])
	return s
}
