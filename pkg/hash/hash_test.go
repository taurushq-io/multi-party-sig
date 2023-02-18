package hash

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/capsule-org/multi-party-sig/pkg/math/curve"
	"github.com/capsule-org/multi-party-sig/pkg/math/sample"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
)

func TestHash_WriteAny(t *testing.T) {
	var err error

	testFunc := func(vs ...interface{}) error {
		h := New()
		for _, v := range vs {
			err = h.WriteAny(v)
			if err != nil {
				return err
			}
		}
		return nil
	}
	b := big.NewInt(35)
	i := new(saferith.Int).SetBig(b, b.BitLen())
	n := new(saferith.Nat).SetBig(b, b.BitLen())
	m := saferith.ModulusFromBytes(b.Bytes())

	assert.NoError(t, testFunc(i, n, m))
	assert.NoError(t, testFunc(sample.Scalar(rand.Reader, curve.Secp256k1{})))
	assert.NoError(t, testFunc(sample.Scalar(rand.Reader, curve.Secp256k1{}).ActOnBase()))
	assert.NoError(t, testFunc([]byte{1, 4, 6}))
}
