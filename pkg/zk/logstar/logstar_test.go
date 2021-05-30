package zklogstar

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
	"google.golang.org/protobuf/proto"
)

func TestLogStar(t *testing.T) {
	verifier := zk.Pedersen
	prover := zk.ProverPaillierPublic

	G := curve.NewIdentityPoint().ScalarBaseMult(curve.NewScalarRandom())

	x := sample.IntervalL()
	C, rho := prover.Enc(x, nil)
	X := curve.NewIdentityPoint().ScalarMult(curve.NewScalarBigInt(x), G)
	public := Public{
		C:      C,
		X:      X,
		G:      G,
		Prover: prover,
		Aux:    verifier,
	}

	proof, err := public.Prove(hash.New(), Private{
		X:   x,
		Rho: rho,
	})
	if err != nil {
		t.Error(err)
		return
	}

	out, err := proto.Marshal(proof)
	if err != nil {
		t.Error(err)
		return
	}
	proof2 := &pb.ZKLogStar{}
	err = proto.Unmarshal(out, proof2)
	if err != nil {
		t.Error(err)
		return
	}

	if !public.Verify(hash.New(), proof2) {
		t.Error("failed to verify")
	}
}
