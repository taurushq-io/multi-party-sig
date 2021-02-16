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

func TestEnc(test *testing.T) {
	prover, verifier, pedersen, C, x, rho := generateParamsEnc()
	proof := NewEncryptionInRange(prover, verifier, pedersen, C, arith.GetBigInt(x), rho)

	assert.NoError(test, proof.Verify(prover, verifier, pedersen, C))
}

func TestEncMarshalling(test *testing.T) {
	prover, verifier, pedersen, C, x, rho := generateParamsEnc()
	proof := NewEncryptionInRange(prover, verifier, pedersen, C, arith.GetBigInt(x), rho)

	b, err := json.Marshal(proof)
	println("size" + strconv.Itoa(len(b)))
	assert.NoError(test, err)
	proofDec := new(EncryptionInRangeProof)
	err = json.Unmarshal(b, proofDec)
	assert.NoError(test, err)
	assert.NoError(test, proofDec.Verify(prover, verifier, pedersen, C))
}

func generateParamsEnc() (prover, verifier *paillier.PublicKey, pedersen *Pedersen, C *paillier.Ciphertext, x kyber.Scalar, rho *paillier.Nonce) {
	group := nist.NewBlakeSHA256P256()

	prover, _ = paillier.KeyGen(256)      // N1 == prover
	verifier, skV := paillier.KeyGen(256) // N0 = nhat == verifier
	pedersen = NewPedersen(verifier.N(), skV.Phi())

	randomStream := group.RandomStream()

	x = group.Scalar().Pick(randomStream)

	C, rho = prover.Enc(arith.GetBigInt(x))
	return
}
