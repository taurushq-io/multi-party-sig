package zkprm

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
)

func TestMod(t *testing.T) {
	sk := paillier.NewSecretKey()
	ped, lambda := sk.GeneratePedersen()

	public := Public{
		ped,
	}

	proof, err := public.Prove(hash.New(), Private{
		Lambda: lambda,
		Phi:    sk.Phi,
	})

	if err != nil {
		t.Error("failed")
		return
	}

	if !public.Verify(hash.New(), proof) {
		t.Error("failed")
	}
}
