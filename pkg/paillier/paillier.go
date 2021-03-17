package paillier

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/sample"
)

func KeyGen() (pk *PublicKey, sk *SecretKey) {
	_, _, n, phi := sample.Paillier()

	pk = NewPublicKey(n)
	sk = NewSecretKey(phi, pk)
	return
}
