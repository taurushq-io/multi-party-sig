package cmp

import (
	"crypto/elliptic"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
	"go.dedis.ch/kyber/v3/group/nist"
)

type Suite interface {
	kyber.Group
	kyber.Encoding
	kyber.XOFFactory
	kyber.Random
}

var suite Suite = nist.NewBlakeSHA256P256()

// Hack
func GetXCoord(p kyber.Point) *mod.Int {
	g := suite.(*nist.Suite128)
	curve := g.Curve
	data, _ := p.MarshalBinary()
	x, _ := elliptic.Unmarshal(curve, data)

	return mod.NewInt(x, g.Params().N)
}
