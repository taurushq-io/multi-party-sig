package party

import (
	"encoding/binary"
	"io"
	"sort"
	"strings"
)

type IDSlice []ID

// NewIDSlice returns a sorted slice from partyIDs.
func NewIDSlice(partyIDs []ID) IDSlice {
	ids := IDSlice(partyIDs).Copy()
	ids.sort()
	return ids
}

// Contains returns true if partyIDs contains id.
// Assumes that the IDSlice is valid.
func (partyIDs IDSlice) Contains(ids ...ID) bool {
	for _, id := range ids {
		if _, ok := partyIDs.search(id); !ok {
			return false
		}
	}
	return true
}

// Valid returns true if the IDSlice is sorted and does not contain any duplicates.
func (partyIDs IDSlice) Valid() bool {
	n := len(partyIDs)
	for i := 1; i < n; i++ {
		if partyIDs[i-1] >= partyIDs[i] {
			return false
		}
	}
	return true
}

// Copy returns an identical copy of the received.
func (partyIDs IDSlice) Copy() IDSlice {
	a := make(IDSlice, len(partyIDs))
	copy(a, partyIDs)
	return a
}

// Remove finds id in partyIDs and returns a copy of the slice if it was found.
func (partyIDs IDSlice) Remove(id ID) IDSlice {
	newPartyIDs := make(IDSlice, 0, len(partyIDs))
	for _, partyID := range partyIDs {
		if partyID != id {
			newPartyIDs = append(newPartyIDs, partyID)
		}
	}
	return newPartyIDs
}

// Len Less and Swap implement sort.Interface.
func (partyIDs IDSlice) Len() int           { return len(partyIDs) }
func (partyIDs IDSlice) Less(i, j int) bool { return partyIDs[i] < partyIDs[j] }
func (partyIDs IDSlice) Swap(i, j int)      { partyIDs[i], partyIDs[j] = partyIDs[j], partyIDs[i] }

// sort is a convenience method: x.Sort() calls Sort(x).
func (partyIDs IDSlice) sort() { sort.Sort(partyIDs) }

// search returns the result of applying SearchStrings to the receiver and x.
func (partyIDs IDSlice) search(x ID) (int, bool) {
	index := sort.Search(len(partyIDs), func(i int) bool { return partyIDs[i] >= x })
	if index >= 0 && index < len(partyIDs) && partyIDs[index] == x {
		return index, true
	}
	return 0, false
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
// It writes the full uncompressed point to w, ie 64 bytes.
func (partyIDs IDSlice) WriteTo(w io.Writer) (int64, error) {
	if partyIDs == nil {
		return 0, io.ErrUnexpectedEOF
	}
	var (
		n   int
		err error
	)

	err = binary.Write(w, binary.BigEndian, uint64(len(partyIDs)))
	if err != nil {
		return 0, err
	}
	nAll := int64(4)
	for _, id := range partyIDs {
		n, err = w.Write([]byte(id))
		nAll += int64(n)
		if err != nil {
			return nAll, err
		}
	}

	return nAll, nil
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (IDSlice) Domain() string {
	return "IDSlice"
}

// String implements fmt.Stringer.
func (partyIDs IDSlice) String() string {
	ss := make([]string, len(partyIDs))
	for i, id := range partyIDs {
		ss[i] = string(id)
	}
	return strings.Join(ss, ", ")
}
