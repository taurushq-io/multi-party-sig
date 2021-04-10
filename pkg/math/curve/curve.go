package curve

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

var Curve = secp256k1.S256()

// Q is the order of the base point
var Q = Curve.Params().N

// P is the order of the underlying field
var P = Curve.Params().P

// ByteSize is the number of bytes required to serialize a field element.
var ByteSize = (Curve.Params().BitSize + 7) / 8
