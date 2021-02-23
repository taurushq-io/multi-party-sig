package encelg

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/secp256k1"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/pedersen"
)

func TestEncElg(t *testing.T) {
	verifierPublic, verifierSecret := paillier.KeyGen(arith.SecParam)
	verifier := pedersen.NewPedersen(verifierPublic.N(), verifierSecret.Phi())
	prover, _ := paillier.KeyGen(arith.SecParam)
	x := arith.Sample(arith.L, nil)
	C, rho := prover.Enc(x, nil)

	a := secp256k1.NewScalarRandom()
	b := secp256k1.NewScalarRandom()
	c := secp256k1.NewScalar()
	c.MultiplyAdd(a, b, secp256k1.NewScalarBigInt(x))
	var A, B, X secp256k1.Point
	A.ScalarBaseMult(a)
	B.ScalarBaseMult(b)
	X.ScalarBaseMult(c)

	proof := NewProof(prover, verifier, C, &A, &B, &X, x, rho, a, b)
	if !proof.Verify(prover, verifier, C, &A, &B, &X) {
		t.Error("failed to verify")
	}
}
