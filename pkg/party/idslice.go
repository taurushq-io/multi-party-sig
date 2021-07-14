package party

import (
	"encoding/binary"
	"io"
	"math/rand"
	"sort"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
)

type IDSlice []ID

func (partyIDs IDSlice) Len() int           { return len(partyIDs) }
func (partyIDs IDSlice) Less(i, j int) bool { return partyIDs[i] < partyIDs[j] }
func (partyIDs IDSlice) Swap(i, j int)      { partyIDs[i], partyIDs[j] = partyIDs[j], partyIDs[i] }

// Sort is a convenience method: x.Sort() calls Sort(x).
func (partyIDs IDSlice) Sort() { sort.Sort(partyIDs) }

// Sorted returns true if partyIDs is sorted
func (partyIDs IDSlice) Sorted() bool {
	for i := range partyIDs {
		if i > 0 && partyIDs[i-1] == partyIDs[i] {
			return false
		}
	}
	return true
}

// Contains returns true if partyIDs contains id.
// Assumes that partyIDs is sorted.
func (partyIDs IDSlice) Contains(id ID) bool {
	_, ok := partyIDs.Search(id)
	return ok
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

func (partyIDs IDSlice) Copy() IDSlice {
	a := make(IDSlice, len(partyIDs))
	copy(a, partyIDs)
	a.Sort()
	return a
}

// Lagrange returns the Lagrange coefficient
//
// We iterate over all points in the set.
// To get the coefficients over a smaller set,
// you should first get a smaller subset.
//
// The following formulas are taken from
// https://en.wikipedia.org/wiki/Lagrange_polynomial
//
//			( x  - x₀) … ( x  - x_k)
// l_j(x) =	---------------------------
//			(x_j - x₀) … (x_j - x_k)
//
//			        x₀ … x_k
// l_j(0) =	---------------------------
//			(x₀ - x_j) … (x_k - x_j)
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

// RandomIDs returns a slice of random IDs with 20 alphanumeric characters
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

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
// It writes the full uncompressed point to w, ie 64 bytes
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
