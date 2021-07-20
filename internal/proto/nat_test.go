package proto

import (
	"testing"
	"testing/quick"

	"github.com/cronokirby/safenum"
	"github.com/stretchr/testify/assert"
)

func testMarshallingNatRoundtrip(bytes []byte) bool {
	x := new(safenum.Nat).SetBytes(bytes)
	m := NatMarshaller{x}
	out := make([]byte, m.Size())
	_, err := m.MarshalTo(out)
	if err != nil {
		return false
	}
	err = m.Unmarshal(out)
	if err != nil {
		return false
	}
	return x.Eq(m.Nat) == 1
}

func TestMarshallingNatRoundtrip(t *testing.T) {
	err := quick.Check(testMarshallingNatRoundtrip, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}

func TestMarshallingNatWithSmallBufferFails(t *testing.T) {
	x := new(safenum.Nat).SetUint64(64)
	m := NatMarshaller{x}
	_, err := m.MarshalTo(nil)
	assert.NotNil(t, err)
}
