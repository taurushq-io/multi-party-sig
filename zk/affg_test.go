package zk

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/arith"
	"github.com/taurusgroup/cmp-ecdsa/paillier"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/nist"
	"strconv"
	"testing"
)

func TestAffG(t *testing.T) {
	group, prover, verifier, pedersen, C, D, Y, X, x, y, rho, rhoY := generateParamsAffG()

	proof := NewAffineGroupCommitmentRange(group, prover, verifier, pedersen, C, D, Y, X, x, y, rho, rhoY)

	require.NoError(t, proof.Verify(group, prover, verifier, pedersen, C, D, Y, X))
}

func TestAffGMarshalling(t *testing.T) {
	group, prover, verifier, pedersen, C, D, Y, X, x, y, rho, rhoY := generateParamsAffG()

	proof := NewAffineGroupCommitmentRange(group, prover, verifier, pedersen, C, D, Y, X, x, y, rho, rhoY)

	b, err := json.Marshal(proof)
	assert.NoError(t, err)
	println("size" + strconv.Itoa(len(b)))
	proofDec := new(AffineGroupCommitmentRange)
	err = json.Unmarshal(b, proofDec)

	assert.NoError(t, proofDec.Verify(group, prover, verifier, pedersen, C, D, Y, X))
}

func generateParamsAffG() (g kyber.Group, prover, verifier *paillier.PublicKey, pedersen *Pedersen, C, D, Y *paillier.Ciphertext, X kyber.Point, x, y kyber.Scalar, rho, rhoY *paillier.Nonce) {
	group := nist.NewBlakeSHA256P256()

	prover, _ = paillier.KeyGen(256)      // N1 == prover
	verifier, skV := paillier.KeyGen(256) // N0 = nhat == verifier
	pedersen = NewPedersen(verifier.N(), skV.Phi())

	randomStream := group.RandomStream()

	x = group.Scalar().Pick(randomStream)
	y = group.Scalar().Pick(randomStream)
	z := group.Scalar().Pick(randomStream)

	C, _ = verifier.Enc(arith.GetBigInt(z))
	Y, rhoY = prover.Enc(arith.GetBigInt(y))
	X = group.Point().Mul(x, nil)
	D, rho = verifier.Affine(C, arith.GetBigInt(x), arith.GetBigInt(y))
	g = group
	return
}

func BenchmarkNewAffineGroupCommitmentRange(b *testing.B) {

}
