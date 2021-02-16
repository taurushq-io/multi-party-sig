package zk

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/taurusgroup/cmp-ecdsa/arith"
	"github.com/taurusgroup/cmp-ecdsa/paillier"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/nist"
	"strconv"
	"testing"
)

func TestLog(test *testing.T) {
	group, prover, verifier, pedersen, C, X, G, x, rho := generateParamsLog()

	proof := NewLog(group, prover, verifier, pedersen, C, X, G, x, rho)

	assert.NoError(test, proof.Verify(group, prover, verifier, pedersen, C, X, G))
}

func TestLogMarshalling(test *testing.T) {
	group, prover, verifier, pedersen, C, X, G, x, rho := generateParamsLog()

	proof := NewLog(group, prover, verifier, pedersen, C, X, G, x, rho)
	b, err := json.Marshal(proof)
	println("size" + strconv.Itoa(len(b)))
	assert.NoError(test, err)
	proofDec := new(Log)
	err = json.Unmarshal(b, proofDec)
	assert.NoError(test, err)

	assert.NoError(test, proofDec.Verify(group, prover, verifier, pedersen, C, X, G))
}

func generateParamsLog() (group kyber.Group, prover, verifier *paillier.PublicKey, pedersen *Pedersen, C *paillier.Ciphertext, X, G kyber.Point, x kyber.Scalar, rho *paillier.Nonce) {
	g := nist.NewBlakeSHA256P256()

	prover, _ = paillier.KeyGen(256)      // N1 == prover
	verifier, skV := paillier.KeyGen(256) // N0 = nhat == verifier
	pedersen = NewPedersen(verifier.N(), skV.Phi())

	randomStream := g.RandomStream()

	x = g.Scalar().Pick(randomStream)
	G = g.Point().Pick(randomStream)
	X = g.Point().Mul(x, G)

	C, rho = prover.Enc(arith.GetBigInt(x))

	group = g
	return
}
