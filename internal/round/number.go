package round

import (
	"encoding/binary"
	"io"
)

// Number is the index of the current round.
// 0 indicates the output round, 1 is the first round.
type Number uint16

// WriteTo implements io.WriterTo interface.
func (i Number) WriteTo(w io.Writer) (int64, error) {
	err := binary.Write(w, binary.BigEndian, uint64(i))
	return 2, err
}

// Domain implements hash.WriterToWithDomain.
func (Number) Domain() string {
	return "Round Number"
}
