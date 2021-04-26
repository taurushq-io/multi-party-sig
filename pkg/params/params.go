package params

const (
	SecParam          = 256
	HashBytes         = 64
	SecBytes          = 32
	StatParam         = 80
	PaillierBits      = 8 * SecParam // = 2048
	BlumPrimeBits     = 4 * SecParam // = 1024
	L                 = 1 * SecParam // = 256
	LPrime            = 5 * SecParam // = 1280
	Epsilon           = 2 * SecParam // = 512
	LPlusEpsilon      = L + Epsilon  //
	LPrimePlusEpsilon = LPrime + Epsilon

	BytesPaillier   = 256
	BytesCiphertext = 2 * 256
	BytesScalar     = 32
)
