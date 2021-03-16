package curve

import (
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

var Curve = secp256k1.S256()

var (
	Q     = Curve.Params().N
	QHalf = new(big.Int).Rsh(Q, 1)
)
