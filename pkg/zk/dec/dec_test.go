package zkdec

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
	"google.golang.org/protobuf/proto"
)

func TestDec(t *testing.T) {
	verifierPedersen := zk.Pedersen
	prover := zk.ProverPaillierPublic

	y := sample.IntervalL()
	x := curve.NewScalarBigInt(y)

	C, rho := prover.Enc(y, nil)

	public := Public{
		C:      C,
		X:      x,
		Prover: prover,
		Aux:    verifierPedersen,
	}
	private := Private{
		Y:   y,
		Rho: rho,
	}

	proof, err := public.Prove(hash.New(), private)
	if err != nil {
		t.Error(err)
	}

	out, err := proto.Marshal(proof)
	if err != nil {
		t.Error(err)
		return
	}
	proof2 := &pb.ZKDec{}
	err = proto.Unmarshal(out, proof2)
	if err != nil {
		t.Error(err)
		return
	}
	if !public.Verify(hash.New(), proof2) {
		t.Error("failed to verify")
	}
}
