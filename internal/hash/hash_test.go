package hash

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cronokirby/safenum"
	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
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
	i := new(safenum.Int).SetBig(b, b.BitLen())
	n := new(safenum.Nat).SetBig(b, b.BitLen())
	m := safenum.ModulusFromBytes(b.Bytes())

	assert.NoError(t, testFunc(i, n, m))
	assert.NoError(t, testFunc(curve.NewIdentityPoint().ScalarBaseMult(sample.Scalar(rand.Reader))))
	assert.NoError(t, testFunc([]byte{1, 4, 6}))
}
