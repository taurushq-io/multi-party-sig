package proto

import (
	"testing"
	"testing/quick"

	"github.com/cronokirby/safenum"
	"github.com/stretchr/testify/assert"
)

var marshaller *NatMarshaller = &NatMarshaller{}

func testMarshallingNatRoundtrip(bytes []byte) bool {
	x := new(safenum.Nat).SetBytes(bytes)
	out := make([]byte, marshaller.Size(x))
	_, err := marshaller.MarshalTo(x, out)
	if err != nil {
		return false
	}
	shouldBeX, err := marshaller.Unmarshal(out)
	if err != nil {
		return false
	}
	return x.Eq(shouldBeX) == 1
}

func TestMarshallingNatRoundtrip(t *testing.T) {
	err := quick.Check(testMarshallingNatRoundtrip, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

func TestMarshallingNatWithSmallBufferFails(t *testing.T) {
	x := new(safenum.Nat).SetUint64(64)
	_, err := marshaller.MarshalTo(x, nil)
	assert.NotNil(t, err)
}
