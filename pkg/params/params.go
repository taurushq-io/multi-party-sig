package params

const (
	SecParam          = 256
	HashBytes         = 64
	SecBytes          = 32
	StatParam         = 80
	PaillierBits      = 8 * SecParam
	BlumPrimeBits     = 4 * SecParam
	L                 = 1 * SecParam
	LPrime            = 5 * SecParam
	Epsilon           = 2 * SecParam
	LPlusEpsilon      = L + Epsilon
	LPrimePlusEpsilon = LPrime + Epsilon
)
