package eddsa

import (
	"crypto/ecdsa"
	"crypto/sha512"

	"github.com/taurusgroup/cmp-ecdsa/pkg/secp256k1"
)

type (
	PrivateKey struct {
		sk secp256k1.Scalar
		pk *PublicKey
	}
	PublicKey struct {
		pk secp256k1.Point
	}
	PublicKeyShares map[uint32]*PublicKey
)

func NewKeyPair(key ecdsa.PrivateKey) (*PrivateKey, *PublicKey) {
	var (
		sk PrivateKey
		pk PublicKey
	)
	digest := sha512.Sum512(key[:32])

	sk.sk.SetBytesWithClamping(digest[:32])
	pk.pk.ScalarBaseMult(&sk.sk)
	sk.pk = &pk

	return &sk, &pk
}

func NewPrivateKeyFromScalar(secret *secp256k1.Scalar, public *PublicKey) *PrivateKey {
	var sk PrivateKey
	if public == nil {
		var pk PublicKey
		pk.pk.ScalarBaseMult(secret)
		public = &pk
	}
	sk.pk = public
	sk.sk.Set(secret)
	return &sk
}

func NewPublicKeyFromPoint(public *secp256k1.Point) *PublicKey {
	var pk PublicKey

	pk.pk.Set(public)

	return &pk
}

func NewPublicKey(key ecdsa.PublicKey) (*PublicKey, error) {
	var (
		err error
		pk  PublicKey
	)
	_, err = pk.pk.SetBytes(key)
	if err != nil {
		return nil, err
	}
	return &pk, nil
}

func (pk *PublicKey) ToEdDSA() ecdsa.PublicKey {
	var key [32]byte
	copy(key[:], pk.pk.Bytes())
	return key[:]
}

func (sk *PrivateKey) PublicKey() *PublicKey {
	return sk.pk
}

func (sk *PrivateKey) Scalar() *secp256k1.Scalar {
	var s secp256k1.Scalar
	return s.Set(&sk.sk)
}

func (pk *PublicKey) Point() *secp256k1.Point {
	var p secp256k1.Point
	return p.Set(&pk.pk)
}

func (pk *PublicKey) Equal(pk0 *PublicKey) bool {
	return 1 == pk.pk.Equal(&pk0.pk)
}
