package party

import (
	"errors"
	"sort"
)

// Set holds a set of party.ID s that can be queried in various ways.
type Set struct {
	set   map[ID]bool
	slice []ID
}

// NewSet generates a set from a slice of ID s.
// It returns an error if any ID represents the 0 value.
// If partyIDs contains duplicates then only one instance will be included in the set.
func NewSet(partyIDs []ID) (*Set, error) {
	n := len(partyIDs)
	s := &Set{
		set:   make(map[ID]bool, n),
		slice: make([]ID, 0, n),
	}
	for _, id := range partyIDs {
		if id == 0 {
			return nil, errors.New("IDs in allPartyIDs cannot be 0")
		}
		if !s.set[id] {
			s.set[id] = true
			s.slice = append(s.slice, id)
		} else {
			return nil, errors.New("partyIDs contains duplicates")
		}
	}
	sort.Slice(s.slice, func(i, j int) bool { return s.slice[i] < s.slice[j] })
	return s, nil
}

// Contains returns true if all parties in partyIDs are included in the set.
func (s *Set) Contains(partyIDs ...ID) bool {
	for _, id := range partyIDs {
		if !s.set[id] {
			return false
		}
	}
	return true
}

// Sorted returns a sorted slice of the parties in the set.
// This structure should not be altered and should be used mainly for iterating over.
// To obtain a copy of the ID,s the caller should instead use
// s.Take(s.N())
func (s *Set) Sorted() []ID {
	return s.slice
}

// Take returns a random subset of size n.
// If n is larger than the number of entries in the set,
// then the full set is returned.
func (s *Set) Take(n Size) []ID {
	if int(n) > len(s.set) {
		n = Size(len(s.set))
	}
	partyIDs := make([]ID, 0, n)
	for id := range s.set {
		partyIDs = append(partyIDs, id)
		if len(partyIDs) == int(n) {
			break
		}
	}
	return partyIDs
}

// N returns the number of ID s in the set.
func (s *Set) N() Size {
	return Size(len(s.set))
}

// Equal returns true
func (s *Set) Equal(otherSet *Set) bool {
	if len(s.set) != len(otherSet.set) {
		return false
	}
	for id := range s.set {
		if !otherSet.set[id] {
			return false
		}
	}
	return true
}

func (s *Set) IsSubsetOf(otherSet *Set) bool {
	return otherSet.Contains(s.slice...)
}

// Range returns a map[ID]bool that can be use for iterating over.
// It returns a pointer to an internal member and should not be modified.
//
// Example:
// for id := range s.Range() {
//     // iterates over the set in a random order.
// }
func (s *Set) Range() map[ID]bool {
	return s.set
}

// Lagrange gives the Lagrange coefficient l_j(x) for x = 0.
//
// We iterate over all points in the set.
// To get the coefficients over a smaller set,
// you should first get a smaller subset.
//
// The following formulas are taken from
// https://en.wikipedia.org/wiki/Lagrange_polynomial
//
//			( x  - x_0) ... ( x  - x_k)
// l_j(x) =	---------------------------
//			(x_j - x_0) ... (x_j - x_k)
//
//			        x_0 ... x_k
// l_j(0) =	---------------------------
//			(x_0 - x_j) ... (x_k - x_j)
//func (s *Set) Lagrange(partyID ID) (*edwards25519.Scalar, error) {
//	var l edwards25519.Scalar
//	return s.lagrange(&l, partyID)
//}
//
//var one, _ = edwards25519.NewScalar().SetCanonicalBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
//
//func (s *Set) lagrange(num *edwards25519.Scalar, partyID ID) (*edwards25519.Scalar, error) {
//	var denum edwards25519.Scalar
//
//	num.Set(one)
//	denum.Set(one)
//
//	if !s.Contains(partyID) {
//		return nil, errors.New("the Set must contain")
//	}
//
//	xJ := partyID.Scalar()
//
//	for id := range s.set {
//		if id == partyID {
//			continue
//		}
//
//		xM := id.Scalar()
//
//		// num = x_0 * ... * x_k
//		num.Multiply(num, xM) // num * xM
//
//		// denum = (x_0 - x_j) ... (x_k - x_j)
//		xM.Subtract(xM, xJ)        // = xM - xJ
//		denum.Multiply(&denum, xM) // denum * (xm - xj)
//	}
//
//	// This should not happen since xM!=xJ
//	if denum.Equal(edwards25519.NewScalar()) == 1 {
//		return nil, errors.New("partyIDs contained idx")
//	}
//
//	denum.Invert(&denum)
//	num.Multiply(num, &denum)
//	return num, nil
//}
