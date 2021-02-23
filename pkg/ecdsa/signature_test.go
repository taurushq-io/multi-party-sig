package eddsa

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"

	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignatureEncode_Decode(t *testing.T) {
	m := []byte("hello")
	_, skBytes, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	sk, pk := NewKeyPair(skBytes)
	//sk := frost.NewPrivateKeyFromScalar(skBytes)
	//pk := sk.PublicKey()

	sig := NewSignature(m, sk, pk)
	//fromReal := uint32(42)
	sigBytes, err := sig.MarshalBinary()
	assert.NoError(t, err)
	//assert.Equal(t, fromReal, from, "from not decoded")
	sig2 := new(Signature)
	err = sig2.UnmarshalBinary(sigBytes)

	assert.NoError(t, err)
	assert.Equal(t, 1, sig.R.Equal(&sig2.R))
	assert.Equal(t, 1, sig.S.Equal(&sig2.S))
}

func TestSignature_Verify(t *testing.T) {
	m := []byte("hello")
	_, skBytes, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	sk, pk := NewKeyPair(skBytes)
	sig := NewSignature(m, sk, pk)
	require.True(t, sig.Verify(m, pk))
}

func TestSignature_VerifyEd25519(t *testing.T) {

	pkBytes, skBytes, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	sk, pk := NewKeyPair(skBytes)

	assert.True(t, bytes.Equal(pk.Point().Bytes(), pkBytes))

	pkComp := edwards25519.NewIdentityPoint().ScalarBaseMult(sk.Scalar())
	assert.Equal(t, 1, pk.Point().Equal(pkComp))

	hm := []byte("hello")
	sig := NewSignature(hm, sk, pk)
	sigEdDSA, _ := sig.MarshalBinary()

	assert.True(t, ed25519.Verify(pkBytes, hm, sigEdDSA))
}
