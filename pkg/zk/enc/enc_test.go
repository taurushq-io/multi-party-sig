package affp

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/pedersen"
)

func TestEnc(t *testing.T) {
	verifierPublic, verifierSecret := paillier.KeyGen(arith.SecParam)
	verifier := pedersen.NewPedersen(verifierPublic.N(), verifierSecret.Phi())
	prover, _ := paillier.KeyGen(arith.SecParam)

	k := arith.Sample(arith.L, nil)
	K, rho := prover.Enc(k, nil)

	proof := NewProof(prover, verifier, K, k, rho)
	if !proof.Verify(prover, verifier, K) {
		t.Error("failed to verify")
	}
}
