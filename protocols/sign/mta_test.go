package sign

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
)

func Test_newMtA(t *testing.T) {
	i := &party.Public{
		Paillier: zk.ProverPaillierPublic,
		Pedersen: zk.Pedersen,
	}
	j := &party.Public{
		Paillier: zk.VerifierPaillierPublic,
		Pedersen: zk.Pedersen,
	}
	ski := zk.ProverPaillierSecret
	skj := zk.VerifierPaillierSecret
	ai, Ai := sample.ScalarPointPair()
	aj, Aj := sample.ScalarPointPair()

	bi := sample.Scalar()
	bj := sample.Scalar()

	Ki, _ := i.Paillier.Enc(bi.BigInt())
	Kj, _ := j.Paillier.Enc(bj.BigInt())

	aibj := curve.NewScalar().Multiply(ai, bj)
	ajbi := curve.NewScalar().Multiply(aj, bi)
	c := curve.NewScalar().Add(aibj, ajbi)

	mta_i_to_j := NewMtA(ai, Ai, Kj, i, j)
	mta_j_to_i := NewMtA(aj, Aj, Ki, j, i)

	msg_i_to_j := mta_i_to_j.ProofAffG(hash.New(), nil)
	msg_j_to_i := mta_j_to_i.ProofAffG(hash.New(), nil)

	alpha_ij := curve.NewScalarBigInt(skj.Dec(msg_i_to_j.D))
	beta_ij := mta_i_to_j.Beta
	alpha_ji := curve.NewScalarBigInt(ski.Dec(msg_j_to_i.D))
	beta_ji := mta_j_to_i.Beta
	gamma_ij := curve.NewScalar().Add(alpha_ij, beta_ij)
	gamma_ji := curve.NewScalar().Add(alpha_ji, beta_ji)
	gamma := curve.NewScalar().Add(gamma_ij, gamma_ji)
	assert.Equal(t, c, gamma, "a•b should be equal to α + β")
	assert.True(t, msg_i_to_j.VerifyAffG(hash.New(), Ai, Kj, i, j, nil))
	assert.True(t, msg_j_to_i.VerifyAffG(hash.New(), Aj, Ki, j, i, nil))

}
