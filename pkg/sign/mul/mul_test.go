package zkmul

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
	"google.golang.org/protobuf/proto"
)

func TestMul(t *testing.T) {
	prover := zk.ProverPaillierPublic
	x := sample.IntervalLN()
	X, rhoX := prover.Enc(x, nil)

	y := sample.IntervalLN()
	Y, _ := prover.Enc(y, nil)

	C := paillier.NewCiphertext().Mul(prover, Y, x)
	_, rho := C.Randomize(prover, nil)

	public := Public{
		X:      X,
		Y:      Y,
		C:      C,
		Prover: prover,
	}
	private := Private{
		X:    x,
		Rho:  rho,
		RhoX: rhoX,
	}

	proof, err := public.Prove(hash.New(nil), private)
	if err != nil {
		t.Error(err)
		return
	}
	out, err := proto.Marshal(proof)
	if err != nil {
		t.Error(err)
		return
	}
	proof2 := &pb.ZKMul{}
	err = proto.Unmarshal(out, proof2)
	if err != nil {
		t.Error(err)
		return
	}

	if !public.Verify(hash.New(nil), proof2) {
		t.Error("failed to verify")
	}
}
