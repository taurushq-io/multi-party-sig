package zkmul

import (
	"math/big"
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/zkcommon"
)

func TestMul(t *testing.T) {
	//TODO
	prover := zkcommon.ProverPaillierPublic
	x := big.NewInt(12)
	X, rhoX := prover.Enc(x, nil)
	y := big.NewInt(13)
	Y, _ := prover.Enc(y, nil)
	var C paillier.Ciphertext
	C.Mul(prover, Y, x)
	_, rho := C.Randomize(prover, nil)

	proof := NewProof(prover, X, Y, &C, x, rho, rhoX)
	if !proof.Verify(prover, X, Y, &C) {
		t.Error("failed to verify")
	}
}
