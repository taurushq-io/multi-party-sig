package party

import (
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

func (partyIDs IDSlice) Sorted() bool {
	for i := range partyIDs {
		if i > 0 && partyIDs[i-1] == partyIDs[i] {
			return false
		}
	}
	return true
}

func (partyIDs IDSlice) Contains(id ID) bool {
	idx := partyIDs.Search(id)
	return partyIDs[idx] == id
}

func (partyIDs IDSlice) GetIndex(id ID) int {
	idx := partyIDs.Search(id)
	if partyIDs[idx] == id {
		return idx
	}
	return -1
}

// Search returns the result of applying SearchStrings to the receiver and x.
func (partyIDs IDSlice) Search(x ID) int {
	return sort.Search(len(partyIDs), func(i int) bool { return partyIDs[i] >= x })
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
//			( x  - x₀) ... ( x  - x_k)
// l_j(x) =	---------------------------
//			(x_j - x₀) ... (x_j - x_k)
//
//			        x₀ ... x_k
// l_j(0) =	---------------------------
//			(x₀ - x_j) ... (x_k - x_j)
func (partyIDs IDSlice) Lagrange(index ID) *curve.Scalar {
	var num, denum, xJ, xM curve.Scalar

	num.SetInt64(1)
	denum.SetInt64(1)

	xJ.SetBytes([]byte(index))

	for _, id := range partyIDs {
		if id == index {
			continue
		}

		xM.SetBytes([]byte(id))

		// num = x₀ * ... * x_k
		num.Multiply(&num, &xM) // num * xM

		// denum = (x₀ - x_j) ... (x_k - x_j)
		xM.Subtract(&xM, &xJ)       // = xM - xJ
		denum.Multiply(&denum, &xM) // denum * (xm - xj)
	}

	denum.Invert(&denum)
	num.Multiply(&num, &denum)
	return &num
}

//func (partyIDs IDSlice) LagrangeAll(indexes IDSlice) []*curve.Scalar {
//
//}

// RandomPartyIDs returns a slice of random IDs with 20 alphanumeric characters
func RandomPartyIDs(n int) IDSlice {
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
