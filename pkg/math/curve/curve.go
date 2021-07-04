package curve

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

// q is the order of the base point
var q = secp256k1.S256().Params().N
