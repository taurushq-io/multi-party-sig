package hash

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
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
	i := new(saferith.Int).SetBig(b, b.BitLen())
	n := new(saferith.Nat).SetBig(b, b.BitLen())
	m := saferith.ModulusFromBytes(b.Bytes())

	assert.NoError(t, testFunc(i, n, m))
	assert.NoError(t, testFunc(sample.Scalar(rand.Reader, curve.Secp256k1{})))
	assert.NoError(t, testFunc(sample.Scalar(rand.Reader, curve.Secp256k1{}).ActOnBase()))
	assert.NoError(t, testFunc([]byte{1, 4, 6}))
}

func TestHash_WriteAny_Collision(t *testing.T) {
	var err error

	testFunc := func(vs ...interface{}) ([]byte, error) {
		h := New()
		for _, v := range vs {
			err = h.WriteAny(v)
			if err != nil {
				return nil, err
			}
		}
		return h.Sum(), nil
	}
	b1 := []byte("1)(big.Int\x02*data_added*")
	b2 := []byte("3")
	n2 := new(big.Int)
	n2.SetString(hex.EncodeToString(b2), 16)
	h1, err := testFunc(b1, n2)
	assert.NoError(t, err)

	b1 = []byte("1")
	b2 = []byte("*data_added*)(big.Int\x023")
	n2 = new(big.Int)
	n2.SetString(hex.EncodeToString(b2), 16)
	h2, err := testFunc(b1, n2)
	assert.NoError(t, err)

	assert.NotEqual(t, h1, h2)
}
