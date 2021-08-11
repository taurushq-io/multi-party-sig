package curve

import (
	"testing"

	"github.com/cronokirby/safenum"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type marshalTester struct {
	S *MarshallableScalar
	P *MarshallablePoint
}

func TestMarshall(t *testing.T) {
	s := marshalTester{
		S: NewMarshallableScalar(Secp256k1{}.NewScalar().SetNat(new(safenum.Nat).SetUint64(0xED))),
		P: NewMarshallablePoint(Secp256k1{}.NewBasePoint()),
	}
	data, err := cbor.Marshal(s)
	require.NoError(t, err)
	var s2 marshalTester
	err = cbor.Unmarshal(data, &s2)
	require.NoError(t, err)
	assert.True(t, s.S.Scalar.Equal(s2.S.Scalar))
	assert.True(t, s.P.Point.Equal(s2.P.Point))
}
