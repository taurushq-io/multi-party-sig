package hash

import (
	"crypto/rand"
	"math/big"
	"testing"

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

	assert.NoError(t, testFunc(big.NewInt(35)))
	assert.NoError(t, testFunc(curve.NewIdentityPoint().ScalarBaseMult(sample.Scalar(rand.Reader))))
	assert.NoError(t, testFunc([]byte{1, 4, 6}))

	var i *big.Int

	assert.Error(t, testFunc(i))

	assert.NoError(t, testFunc(big.NewInt(35), []byte{1, 4, 6}))
}
