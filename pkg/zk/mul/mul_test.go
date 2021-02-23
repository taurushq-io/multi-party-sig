package affp

import (
	"math/big"
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
)

func TestNewProof(t *testing.T) {
	pk, _ := paillier.KeyGen(256)
	x := big.NewInt(12)
	X, rhoX := pk.Enc(x, nil)
	y := big.NewInt(13)
	Y, _ := pk.Enc(y, nil)
	var C paillier.Ciphertext
	C.Mul(pk, Y, x)
	_, rho := C.Randomize(pk, nil)

	proof := NewProof(pk, X, Y, &C, x, rho, rhoX)
	if !proof.Verify(pk, X, Y, &C) {
		t.Error("failed to verify")
	}
}
