package zkmulstar

import (
	"crypto/rand"
	"testing"

	"github.com/cronokirby/safenum"
	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/zk"
)

func TestMulG(t *testing.T) {
	verifierPaillier := zk.VerifierPaillierPublic
	verifierPedersen := zk.Pedersen

	c := new(safenum.Int).SetUint64(12)
	C, _ := verifierPaillier.Enc(c)

	var X curve.Point
	x := sample.IntervalL(rand.Reader)
	X.ScalarBaseMult(curve.NewScalarInt(x))

	D := C.Clone().Mul(verifierPaillier, x)
	n := verifierPaillier.N()
	rho := sample.UnitModN(rand.Reader, n)
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
	proof := NewProof(hash.New(), public, private)
	//out, err := proof.Marshal()
	//require.NoError(t, err, "failed to marshal proof")
	//proof2 := &Proof{}
	//require.NoError(t, proof2.Unmarshal(out), "failed to unmarshal proof")
	//out2, err := proof2.Marshal()
	//require.NoError(t, err, "failed to marshal 2nd proof")
	//proof3 := &Proof{}
	//require.NoError(t, proof3.Unmarshal(out2), "failed to unmarshal 2nd proof")

	assert.True(t, proof.Verify(hash.New(), public))
}
