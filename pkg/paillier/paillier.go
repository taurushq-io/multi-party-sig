package paillier

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
)

func KeyGen() (pk *PublicKey, sk *SecretKey) {
	_, _, n, phi := sample.Paillier()

	pk = NewPublicKey(n)
	sk = NewSecretKey(phi, pk)
	return
}
