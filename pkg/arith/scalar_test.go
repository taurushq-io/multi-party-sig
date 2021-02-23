package arith

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/group/mod"
	"go.dedis.ch/kyber/v3/group/nist"
	"math/big"
	"testing"
)

func TestScalarConv(t *testing.T) {
	g := nist.NewBlakeSHA256P256()
	b := new(big.Int).SetBit(new(big.Int), 200, 1)
	for i := 0; i < 100; i++ {

		r, _ := rand.Int(rand.Reader, b)

		s := g.Scalar().SetBytes(r.Bytes())
		assert.True(t, s.(*mod.Int).V.Cmp(r) == 0)
	}

}
