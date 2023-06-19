package curve

import (
	"encoding"

	"github.com/cronokirby/saferith"
)

// Curve represents the starting point for working with an Elliptic Curve group.
//
// The expectation is that this interface will be implemented by a nominal struct,
// and use associated types for its Point and Scalar. These types are only
// expected to work with other members of their type, and not with arbitrary elements
// satisfying the Point and Scalar interfaces.
type Curve interface {
	// NewPoint creates an identity point.
	NewPoint() Point
	// NewBasePoint creates the generate of this group.
	NewBasePoint() Point
	// NewScalar creates a scalar with the value of 0.
	NewScalar() Scalar
	// Name returns the name of this curve.
	//
	// This should be unique between curves.
	Name() string
	// ScalarBits returns the number of significant bits in a scalar.
	ScalarBits() int
	// SafeScalarBytes returns the number of random bytes need to sample a scalar through modular reduction.
	//
	// Usually, this is going to be the number of bytes in the scalar, plus an extra
	// security parameters worth of bytes, say 32. This is to make sure that the modular
	// reduction doesn't introduce any bias.
	SafeScalarBytes() int
	// Order returns a Modulus holding order of this group.
	Order() *saferith.Modulus
}

// Scalar represents a number modulo the order of some Elliptic Curve group.
//
// Scalars act on points in the group, but should also form a field amongst themselves.
//
// The methods on Scalar are all intended to be mutable, modifying the current scalar,
// before returning it.
//
// When implementing this interface, you're only expected to make operations work
// with elements of the same type. It's perfectly fine to cast incoming elements
// to your concrete type. This interface is not designed to be able to handle
// different Scalar types, but we can't encode that in the type system.
type Scalar interface {
	// This should encode the Scalar as Big Endian bytes, without failure.
	encoding.BinaryMarshaler
	// This should decode the Scalar from Big Endian bytes.
	encoding.BinaryUnmarshaler
	// Curves returns the Curve associated with this kind of Scalar.
	Curve() Curve
	// Add mutates this Scalar, by adding in another.
	Add(Scalar) Scalar
	// Sub mutates this Scalar, by subtracting another.
	//
	// This should be equivalent to .Add(_.Negate()), but may be implemented faster,
	// and won't mutate its input.
	Sub(Scalar) Scalar
	// Negate mutates this Scalar, replacing it with its negation.
	Negate() Scalar
	// Mul mutates this Scalar, replacing it with another.
	Mul(Scalar) Scalar
	// Invert mutates this Scalar, replacing it with its multiplicative inverse.
	Invert() Scalar
	// Equal checks if this Scalar is equal to another.
	//
	// This check should be done in constant time.
	Equal(Scalar) bool
	// IsZero checks if this Scalar is equal to 0.
	//
	// This check should be done in constant time.
	//
	// While this can be accomplished through the Equal method, IsZero may
	// be implemented more efficiently.
	IsZero() bool
	// Set mutates this Scalar, replacing its value with another.
	Set(Scalar) Scalar
	// SetNat mutates this Scalar, replacing it with the value of a number.
	//
	// This number must be interpreted modulo the order of the group.
	SetNat(*saferith.Nat) Scalar
	// Act acts on a Point with this Scalar, returning a new Point.
	//
	// This shouldn't mutate the Scalar, or the Point.
	Act(Point) Point
	// Act acts on the Base Point with this Scalar, returning a new Point.
	//
	// This can be accomplished with Act, but can be made more efficient, in many cases.
	ActOnBase() Point

	IsOverHalfOrder() bool
}

// Point represents an element of our Elliptic Curve group.
//
// The methods on Point are intended to be immutable, never modifying the receiver.
//
// When implementing this interface, you're only expected to make operations work
// with elements of the same type. It's perfectly fine to cast incoming elements
// to your concrete type. This interface is not designed to be able to handle
// different Point types, but we can't encode that in the type system.
type Point interface {
	// You're free to implement the binary marshalling however you'd like.
	//
	// This marshalling should also work with the identity element, ideally,
	// but this isn't strictly necessary.
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	// Curve returns the Elliptic Curve group associated with this type of Point.
	Curve() Curve
	// Add returns a new Point, by adding another Point to this one.
	//
	// This should not mutate this point.
	Add(Point) Point
	// Sub returns a new Point, by subtracting another Point from this one.
	//
	// This can be implemented with Add and Negate, but can be more efficient.
	//
	// This shouldn't mutate this point.
	Sub(Point) Point
	// Negate returns the negated version of this point.
	//
	// This does not mutate this point.
	Negate() Point
	// Equal checks if this point is equal to another.
	//
	// This check should, ideally, be done in constant time.
	Equal(Point) bool
	// IsIdentity checks if this is the identity element of this group.
	IsIdentity() bool
	// XScalar is an optional method, returning the x coordinate of this Point as a Scalar.
	//
	// This is used in ECDSA, but isn't available on every curve, necessarily.
	//
	// If you choose not to implement this method, simply return nil.
	XScalar() Scalar
}

// MakeInt converts a scalar into an Int.
func MakeInt(s Scalar) *saferith.Int {
	bytes, err := s.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return new(saferith.Int).SetBytes(bytes)
}

// FromHash converts a hash value to a Scalar.
//
// There is some disagreement about how this should be done.
// [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
//
// Taken from crypto/ecdsa.
func FromHash(group Curve, h []byte) Scalar {
	order := group.Order()
	orderBits := order.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(h) > orderBytes {
		h = h[:orderBytes]
	}
	s := new(saferith.Nat).SetBytes(h)
	excess := len(h)*8 - orderBits
	if excess > 0 {
		s.Rsh(s, uint(excess), -1)
	}
	return group.NewScalar().SetNat(s)
}
