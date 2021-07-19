package sign

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
	"github.com/taurusgroup/cmp-ecdsa/protocols/refresh"
)

func Test_newMtA(t *testing.T) {
	i := &refresh.Public{
		Paillier: zk.ProverPaillierPublic,
		Pedersen: zk.Pedersen,
	}
	j := &refresh.Public{
		Paillier: zk.VerifierPaillierPublic,
		Pedersen: zk.Pedersen,
	}
	ski := zk.ProverPaillierSecret
	skj := zk.VerifierPaillierSecret
	ai, Ai := sample.ScalarPointPair(rand.Reader)
	aj, Aj := sample.ScalarPointPair(rand.Reader)

	bi := sample.Scalar(rand.Reader)
	bj := sample.Scalar(rand.Reader)

	Ki, _ := i.Paillier.Enc(bi.BigInt())
	Kj, _ := j.Paillier.Enc(bj.BigInt())

	aibj := curve.NewScalar().Multiply(ai, bj)
	ajbi := curve.NewScalar().Multiply(aj, bi)
	c := curve.NewScalar().Add(aibj, ajbi)

	mta_i_to_j := NewMtA(ai, Ai, Kj, i, j)
	mta_j_to_i := NewMtA(aj, Aj, Ki, j, i)

	msg_i_to_j := mta_i_to_j.ProofAffG(hash.New(), nil)
	msg_j_to_i := mta_j_to_i.ProofAffG(hash.New(), nil)

	alpha_ij, err := skj.Dec(msg_i_to_j.D)
	assert.NoError(t, err, "decryption should pass")
	gamma_ij_int := alpha_ij.Sub(alpha_ij, mta_i_to_j.BetaNeg)
	alpha_ji, err := ski.Dec(msg_j_to_i.D)
	assert.NoError(t, err, "decryption should pass")
	gamma_ji_int := alpha_ji.Sub(alpha_ji, mta_j_to_i.BetaNeg)
	gamma_ij := curve.NewScalarBigInt(gamma_ij_int)
	gamma_ji := curve.NewScalarBigInt(gamma_ji_int)
	gamma := curve.NewScalar().Add(gamma_ij, gamma_ji)
	assert.Equal(t, c, gamma, "a•b should be equal to α + β")
	assert.True(t, msg_i_to_j.VerifyAffG(hash.New(), Ai, Kj, i, j, nil))
	assert.True(t, msg_j_to_i.VerifyAffG(hash.New(), Aj, Ki, j, i, nil))

}
