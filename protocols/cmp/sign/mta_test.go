package sign

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
	"github.com/taurusgroup/cmp-ecdsa/protocols/cmp/keygen"
)

func Test_newMtA(t *testing.T) {
	i := &keygen.Public{
		Paillier: zk.ProverPaillierPublic,
		Pedersen: zk.Pedersen,
	}
	j := &keygen.Public{
		Paillier: zk.VerifierPaillierPublic,
		Pedersen: zk.Pedersen,
	}
	ski := zk.ProverPaillierSecret
	skj := zk.VerifierPaillierSecret
	ai, Ai := sample.ScalarPointPair(rand.Reader)
	aj, Aj := sample.ScalarPointPair(rand.Reader)

	bi := sample.Scalar(rand.Reader)
	bj := sample.Scalar(rand.Reader)

	Bi, _ := i.Paillier.Enc(bi.Int())
	Bj, _ := j.Paillier.Enc(bj.Int())

	aibj := curve.NewScalar().Multiply(ai, bj)
	ajbi := curve.NewScalar().Multiply(aj, bi)
	c := curve.NewScalar().Add(aibj, ajbi)

	mta_i_to_j := NewMtA(ai, Ai, Bi, Bj, ski, j.Paillier)
	mta_j_to_i := NewMtA(aj, Aj, Bj, Bi, skj, i.Paillier)

	msg_i_to_j := mta_i_to_j.ProofAffG(hash.New(), j.Pedersen)
	msg_j_to_i := mta_j_to_i.ProofAffG(hash.New(), i.Pedersen)

	err := mta_i_to_j.Input(hash.New(), j.Pedersen, msg_j_to_i, Aj)
	require.NoError(t, err, "decryption should pass")
	err = mta_j_to_i.Input(hash.New(), i.Pedersen, msg_i_to_j, Ai)
	require.NoError(t, err, "decryption should pass")

	gamma_ij := mta_i_to_j.Share()
	gamma_ji := mta_j_to_i.Share()
	gamma := curve.NewScalar().Add(gamma_ij, gamma_ji)
	assert.Equal(t, c, gamma, "a•b should be equal to α + β")

}
