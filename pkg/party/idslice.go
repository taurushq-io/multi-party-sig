package party

import (
	"encoding/binary"
	"io"
	"math/rand"
	"sort"
	"strings"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
)

type IDSlice []ID

// NewIDSlice returns a sorted slice of partyIDs.
func NewIDSlice(partyIDs []ID) IDSlice {
	ids := IDSlice(partyIDs).Copy()
	if ids.Sorted() {
		return ids
	}
	ids.Sort()
	return ids
}

func (partyIDs IDSlice) Len() int           { return len(partyIDs) }
func (partyIDs IDSlice) Less(i, j int) bool { return partyIDs[i] < partyIDs[j] }
func (partyIDs IDSlice) Swap(i, j int)      { partyIDs[i], partyIDs[j] = partyIDs[j], partyIDs[i] }

// Sort is a convenience method: x.Sort() calls Sort(x).
func (partyIDs IDSlice) Sort() { sort.Sort(partyIDs) }

// Sorted returns true if partyIDs is sorted.
func (partyIDs IDSlice) Sorted() bool { return sort.IsSorted(partyIDs) }

// Contains returns true if partyIDs contains id.
// Assumes that partyIDs is sorted.
func (partyIDs IDSlice) Contains(ids ...ID) bool {
	for _, id := range ids {
		if _, ok := partyIDs.Search(id); !ok {
			return false
		}
	}
	return true
}

// ContainsDuplicates returns true if a duplicated item is contained.
// Assumes partyIDs is sorted.
func (partyIDs IDSlice) ContainsDuplicates() bool {
	for i := range partyIDs {
		if i == 0 {
			continue
		}
		if partyIDs[i-1] == partyIDs[i] {
			return true
		}
	}
	return false
}

// GetIndex returns the index of id in partyIDs.
// If no index was found, return -1.
// Assumes that partyIDs is sorted.
func (partyIDs IDSlice) GetIndex(id ID) int {
	if idx, ok := partyIDs.Search(id); ok {
		return idx
	}
	return -1
}

// Search returns the result of applying SearchStrings to the receiver and x.
func (partyIDs IDSlice) Search(x ID) (int, bool) {
	index := sort.Search(len(partyIDs), func(i int) bool { return partyIDs[i] >= x })
	if index >= 0 && index < len(partyIDs) && partyIDs[index] == x {
		return index, true
	}
	return 0, false
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

// Lagrange returns the Lagrange coefficient
//
// When a subset participants multiply their polynomial shares with the corresponding lagrange
// coefficients, they get an additive sharing of the secret key.
//
// We iterate over all points in the set.
// To get the coefficients over a smaller set,
// you should first get a smaller subset.
//
// The following formulas are taken from
// https://en.wikipedia.org/wiki/Lagrange_polynomial
//			        x₀ … xₖ
// lⱼ(0) =	---------------------------
//			(x₀ - xⱼ) … (xₖ - xⱼ)
func (partyIDs IDSlice) Lagrange(index ID) *curve.Scalar {

	num := curve.NewScalarUInt32(1)
	denum := curve.NewScalarUInt32(1)

	xJ := index.Scalar()

	for _, id := range partyIDs {
		if id == index {
			continue
		}

		xM := id.Scalar()

		// num = x₀ * … * x_k
		num.Multiply(num, xM) // num * xM

		// denum = (x₀ - x_j) … (x_k - x_j)
		xM.Subtract(xM, xJ)       // = xM - xJ
		denum.Multiply(denum, xM) // denum * (xm - xj)
	}

	denum.Invert(denum)
	num.Multiply(num, denum)
	return num
}

// RandomIDs returns a slice of random IDs with 20 alphanumeric characters.
func RandomIDs(n int) IDSlice {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	partyIDs := make(IDSlice, n)
	for i := range partyIDs {
		b := make([]byte, 20)
		for j := range b {
			b[j] = letters[rand.Intn(len(letters))]
		}
		partyIDs[i] = ID(b)
	}
	partyIDs.Sort()
	return partyIDs
}

// Equal checks if both IDSlice are equal, assuming they are sorted.
func (partyIDs IDSlice) Equal(otherPartyIDs IDSlice) bool {
	if len(partyIDs) != len(otherPartyIDs) {
		return false
	}
	for i := range partyIDs {
		if partyIDs[i] != otherPartyIDs[i] {
			return false
		}
	}
	return true
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
// It writes the full uncompressed point to w, ie 64 bytes.
func (partyIDs IDSlice) WriteTo(w io.Writer) (int64, error) {
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

// Domain implements WriterToWithDomain, and separates this type within hash.Hash.
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
