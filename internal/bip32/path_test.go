package bip32

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

func (left *Path) eq(right *Path) bool {
	if len(left.indices) != len(right.indices) {
		return false
	}

	for i, index := range left.indices {
		if index != right.indices[i] {
			return false
		}
	}

	return true
}

func TestPathFrom(t *testing.T) {
	spec := "44'/0/0'/348"

	result, err := PathFrom(spec)

	if err != nil {
		t.Errorf("") // FIXME
	}

	desired := Path{indices: []uint32{
		newIndex(44, true),
		newIndex(0, false),
		newIndex(0, true),
		newIndex(348, false),
	}}

	if !result.eq(&desired) {
		t.Errorf("The BIP32 path %s fails to parse correctly", spec)
	}
}

// Test cases are taken from
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_Vectors.
// A test case key string `keyString` was decoded as follows:
//
//	import "github.com/btcsuite/btcutil/base58"
//
//	payload, version, err := base58.CheckDecode(keyString)
//	chainKey := payload[12:12+32]
//	paddedPrivateOrPublicKeyBytes := payload[12+32+1:]
//
// This extraction has been precomputed to avoid adding the base58 dependency.
func TestDerive(t *testing.T) {
	seedString := "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
	seed, err := hex.DecodeString(seedString)
	if err != nil {
		panic("Bug in test: Expected seed to be a hex string")
	}

	// Extracted from "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
	masterChainKey, err := hex.DecodeString("60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689")
	if err != nil {
		panic("Bug in test: Expected to be a hex string")
	}

	// Extracted from "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
	childChainKey, err := hex.DecodeString("f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c")
	if err != nil {
		panic("Bug in test: Expected to be a hex string")
	}

	computedMasterPrivateKey, computedMasterChainKey, err := DeriveMaster(seed)
	if err != nil {
		panic("Expected derivation of master key from seed to succeed")
	}

	// We do not yet check that the computed master private key is correct.
	//
	// It is a `curve.Scalar`, which hides its underlying value.
	// To check correctness requires accessing its bits
	// or converting the correct bits to a `curve.Scalar`
	// and then calling the method `curve.Scalar.Equal`.
	_ = computedMasterPrivateKey

	if !bytes.Equal(masterChainKey, computedMasterChainKey) {
		t.Errorf("Expected chain key \n\t0x%x but have \n\t0x%x", masterChainKey, computedMasterChainKey)
	}

	path, err := PathFrom("0")
	computedAdjust, computedChildChainKey, err := DeriveScalarForPath(
		computedMasterPrivateKey.ActOnBase().(*curve.Secp256k1Point),
		computedMasterChainKey,
		path)
	if err != nil {
		panic("Expected derivation of child from master key to succeed")
	}

	if !bytes.Equal(childChainKey, computedChildChainKey) {
		t.Errorf("Expected chain key \n\t0x%x but have \n\t0x%x", childChainKey, computedChildChainKey)
	}

	_ = computedAdjust
}
