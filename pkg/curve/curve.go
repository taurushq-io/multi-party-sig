package curve

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

var Curve = secp256k1.S256()

var Q = Curve.Params().N
