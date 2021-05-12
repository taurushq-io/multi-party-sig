package zkenc

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
	"google.golang.org/protobuf/proto"
)

func TestEnc(t *testing.T) {
	verifier := zk.Pedersen
	prover := zk.ProverPaillierPublic

	k := sample.IntervalL()
	K, rho := prover.Enc(k, nil)
	public := Public{
		K:      K,
		Prover: prover,
		Aux:    verifier,
	}

	proof, err := public.Prove(hash.New(nil), Private{
		K:   k,
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
	proof2 := &pb.ZKEnc{}
	err = proto.Unmarshal(out, proof2)
	if err != nil {
		t.Error(err)
		return
	}

	if !public.Verify(hash.New(nil), proof2) {
		t.Error("failed to verify")
	}
}
