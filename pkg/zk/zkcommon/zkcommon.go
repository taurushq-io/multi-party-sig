package zkcommon

import (
	"crypto/sha512"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/curve"
)

type Byteable interface {
	Bytes() []byte
}

func MakeChallenge(domain string, components ...Byteable) []byte {
	h := sha512.New()

	domainBytes := make([]byte, 32)

	copy(domainBytes, domain)
	_, _ = h.Write(domainBytes)

	for _, c := range components {
		_, _ = h.Write(c.Bytes())
	}

	return h.Sum(nil)
}

func MakeChallengeFq(domain string, components ...Byteable) *big.Int {
	var e big.Int
	digest := MakeChallenge(domain, components...)
	negate := digest[0] & 1 == 1
	digest[0] |= 1
	e.SetBytes(digest)
	e.Mod(&e, curve.Q)
	if negate {
		e.Neg(&e)
	}
	return &e
}

func MakeChallengeScalar(domain string, components ...Byteable) *curve.Scalar {
	var e curve.Scalar
	digest := MakeChallenge(domain, components...)
	e.SetBytes(digest)
	return &e
}