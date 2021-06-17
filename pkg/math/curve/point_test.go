package curve

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

func TestNewBasePoint(t *testing.T) {
	var g1, g2 Point
	two := NewScalar().SetUInt32(2)
	g1.Add(NewBasePoint(), NewBasePoint())
	g2.ScalarBaseMult(two)
	assert.True(t, g1.Equal(g2))
}

func TestPoint_Negate(t *testing.T) {
	var G, Gneg, GminGneg Point
	G = *NewBasePoint()
	Gneg.Negate(&G)
	GminGneg.Add(&G, &Gneg)
	assert.True(t, GminGneg.IsIdentity())
}

func TestPoint_Equal(t *testing.T) {
	id := *NewIdentityPoint()
	assert.True(t, id.Equal(id))
	assert.True(t, id.Equal(&id))
	assert.True(t, (&id).Equal(&id))
	assert.True(t, (&id).Equal(id))
}

func TestPoint_Subtract(t *testing.T) {
	g := NewBasePoint()
	p := NewIdentityPoint().Subtract(g, g)
	assert.True(t, p.IsIdentity())
	p.Subtract(NewIdentityPoint(), g)
	gneg := NewIdentityPoint().Negate(g)
	assert.True(t, p.Equal(gneg))
}

func TestPoint_WriteTo(t *testing.T) {
	b := bytes.NewBuffer(nil)
	g := NewBasePoint()
	n, err := g.WriteTo(b)
	assert.NoError(t, err)
	assert.EqualValues(t, n, params.BytesPoint)
	data := b.Bytes()
	Gx, _ := hex.DecodeString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	assert.Equal(t, data[1:], Gx)

	b.Reset()
	n, err = NewIdentityPoint().WriteTo(b)
	assert.Error(t, err)
	assert.EqualValues(t, 0, n)
}
