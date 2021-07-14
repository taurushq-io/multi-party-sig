package zkmulstar

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
)

func TestMulG(t *testing.T) {
	verifierPaillier := zk.VerifierPaillierPublic
	verifierPedersen := zk.Pedersen

	c := big.NewInt(12)
	C, _ := verifierPaillier.Enc(c)

	var X curve.Point
	x := sample.IntervalL(rand.Reader)
	X.ScalarBaseMult(curve.NewScalarBigInt(x))

	D := C.Clone().Mul(verifierPaillier, x)
	rho := sample.UnitModN(rand.Reader, verifierPaillier.N)
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
	//for i := 0; i < 100; i++ {
	proof := NewProof(hash.New(), public, private)
	out, err := proof.Marshal()
	require.NoError(t, err, "failed to marshal proof")
	proof2 := &Proof{}
	require.NoError(t, proof2.Unmarshal(out), "failed to unmarshal proof")
	assert.Equal(t, proof, proof2)
	out2, err := proof2.Marshal()
	assert.Equal(t, out, out2)
	proof3 := &Proof{}
	require.NoError(t, proof3.Unmarshal(out2), "failed to marshal 2nd proof")
	assert.Equal(t, proof, proof3)

	assert.True(t, proof2.Verify(hash.New(), public))
	//}
}
