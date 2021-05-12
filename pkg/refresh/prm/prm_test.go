package zkprm

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

func TestMod(t *testing.T) {
	_, _, n, phi := sample.Paillier()
	s, T, lambda := sample.Pedersen(n, phi)

	public := Public{
		&pedersen.Parameters{
			N: n,
			S: s,
			T: T,
		},
	}

	proof, err := public.Prove(hash.New(nil), Private{
		Lambda: lambda,
		Phi:    phi,
	})

	if err != nil {
		t.Error("failed")
		return
	}

	if !public.Verify(hash.New(nil), proof) {
		t.Error("failed")
	}
}
