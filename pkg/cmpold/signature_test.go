package cmpold

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/group/nist"
)

func TestSignature_Verify(t *testing.T) {

	g := nist.NewBlakeSHA256P256()
	message := []byte{byte(1), byte(2)}
	hashedMessage := HashMessageToScalar(message)

	sk := g.Scalar().Pick(g.RandomStream())
	pk := g.Point().Mul(sk, nil)

	k := g.Scalar().Pick(g.RandomStream())
	kInv := g.Scalar().Inv(k)
	R := g.Point().Mul(k, nil)
	r := GetXCoord(R)

	s := g.Scalar().Mul(r, sk)
	s = s.Add(s, hashedMessage)
	s = s.Mul(s, kInv)
	sig := Signature{
		M: hashedMessage,
		R: R,
		S: s,
	}

	assert.True(t, sig.Verify(pk))

}
