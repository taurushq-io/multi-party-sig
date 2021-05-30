package zkmulstar

import (
	"math/big"
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
	"google.golang.org/protobuf/proto"
)

func TestMulG(t *testing.T) {
	verifierPaillier := zk.VerifierPaillierPublic
	verifierPedersen := zk.Pedersen

	c := big.NewInt(12)
	C, _ := verifierPaillier.Enc(c, nil)

	var X curve.Point
	x := sample.IntervalL()
	X.ScalarBaseMult(curve.NewScalarBigInt(x))

	D := paillier.NewCiphertext()
	D.Mul(verifierPaillier, C, x)
	rho := verifierPaillier.Nonce()
	D.Randomize(verifierPaillier, rho)

	public := Public{
		C:        C,
		D:        D,
		X:        &X,
		Verifier: verifierPaillier,
		Aux:      verifierPedersen,
	}
	private := Private{
		X:   x,
		Rho: rho,
	}
	proof, err := public.Prove(hash.New(), private)
	if err != nil {
		t.Error(err)
		return
	}
	out, err := proto.Marshal(proof)
	if err != nil {
		t.Error(err)
		return
	}
	proof2 := &pb.ZKMulStar{}
	err = proto.Unmarshal(out, proof2)
	if err != nil {
		t.Error(err)
		return
	}

	if !public.Verify(hash.New(), proof2) {
		t.Error("failed to verify")
	}
}
