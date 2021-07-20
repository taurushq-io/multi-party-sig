package proto

import (
	"encoding/json"
	"fmt"

	"github.com/cronokirby/safenum"
)

// NatMarshaller is a wrapper used to direct serialization of safenum.Nat
//
// Unlike Nat, this struct can be used directly in protobuf fields, using
// the `custom_type` extension.
type NatMarshaller struct {
	*safenum.Nat
}

// Marshal writes out the data contained in this struct to a slice.
func (m NatMarshaller) Marshal() ([]byte, error) {
	return m.Bytes(), nil
}

// Marshal writes out the data to an existing slice, returning an error if the slice is small.
func (m *NatMarshaller) MarshalTo(data []byte) (n int, err error) {
	required := m.Size()
	if len(data) < required {
		return 0, fmt.Errorf("NatMarshaller.MarshalTo: output buffer too small. Found %d, required %d", len(data), required)
	}
	m.FillBytes(data)
	return required, nil
}

// Unmarshal parses bytes to create a Nat value.
func (m *NatMarshaller) Unmarshal(data []byte) error {
	m.SetBytes(data)
	return nil
}

// Size returns the number of bytes needed to store the value contained in this truct.
func (m *NatMarshaller) Size() int {
	return (m.AnnouncedLen() + 7) / 8
}

// MarshalJSON produces JSON from this struct
func (m NatMarshaller) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.Bytes())
}

// UnmarshalJSON reads this struct from JSON
func (m *NatMarshaller) UnmarshalJSON(data []byte) error {
	// Since base64 uses 4 characters for every 3 bytes, this gives us a reasonable
	// estimate of how many byes we'll have
	theBytes := make([]byte, 0, 3*len(data)/4)
	if err := json.Unmarshal(data, &theBytes); err != nil {
		return err
	}
	m.SetBytes(theBytes)
	return nil
}
