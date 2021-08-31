package keygen

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/bip32"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
)

func adjust(with curve.Scalar, priv curve.Scalar, pub curve.Point, pubShares map[party.ID]curve.Point) {
	withG := with.ActOnBase()
	pub.Add(withG)
	for _, v := range pubShares {
		v.Add(withG)
	}
}

// Result contains all the information produced after key generation, from the perspective
// of a single participant.
type Result struct {
	// ID is the identifier for this participant.
	ID party.ID
	// Threshold is the number of accepted corruptions while still being able to sign.
	Threshold int
	// PrivateShare is the fraction of the secret key owned by this participant.
	PrivateShare curve.Scalar
	// PublicKey is the shared public key for this consortium of signers.
	//
	// This key can be used to verify signatures produced by the consortium.
	PublicKey curve.Point
	// ChainKey is the additional randomness we've agreed upon.
	//
	// This is only ever useful if you do BIP-32 key derivation, or something similar.
	ChainKey []byte
	// VerificationShares is a map between parties and a commitment to their private share.
	//
	// This will later be used to verify the integrity of the signing protocol.
	VerificationShares map[party.ID]curve.Point
}

// Curve returns the Elliptic Curve Group associated with this result.
func (r *Result) Curve() curve.Curve {
	return r.PublicKey.Curve()
}

// Clone creates a deep clone of this struct, and all the values contained inside
func (r *Result) Clone() *Result {
	chainKeyCopy := make([]byte, len(r.ChainKey))
	copy(chainKeyCopy, r.ChainKey)
	verificationSharesCopy := make(map[party.ID]curve.Point)
	for k, v := range r.VerificationShares {
		verificationSharesCopy[k] = v
	}
	return &Result{
		ID:                 r.ID,
		Threshold:          r.Threshold,
		PrivateShare:       r.Curve().NewScalar().Set(r.PrivateShare),
		PublicKey:          r.PublicKey,
		ChainKey:           chainKeyCopy,
		VerificationShares: verificationSharesCopy,
	}
}

// DeriveChild adjusts the shares to represent the derived public key at a certain index.
//
// This will panic if the group is not curve.Secp256k1
//
// This derivation works according to BIP-32, see:
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
func (r *Result) DeriveChild(i uint32) (*Result, error) {
	publicKey, ok := r.PublicKey.(*curve.Secp256k1Point)
	if !ok {
		return nil, errors.New("DeriveChild called on non secp256k1 curve")
	}
	scalar, newChainKey, err := bip32.DeriveScalar(publicKey, r.ChainKey, i)
	if err != nil {
		return nil, err
	}
	newR := r.Clone()
	adjust(scalar, newR.PrivateShare, newR.PublicKey, newR.VerificationShares)
	newR.ChainKey = newChainKey
	return newR, nil
}

// TaprootResult is like result, but for Taproot / BIP-340 keys.
//
// The main difference is that our public key is an actual taproot public key.
type TaprootResult struct {
	// ID is the identifier for this participant.
	ID party.ID
	// Threshold is the number of accepted corruptions while still being able to sign.
	Threshold int
	// PrivateShare is the fraction of the secret key owned by this participant.
	PrivateShare *curve.Secp256k1Scalar
	// PublicKey is the shared public key for this consortium of signers.
	//
	// This key can be used to verify signatures produced by the consortium.
	PublicKey taproot.PublicKey
	// ChainKey is the additional randomness we've agreed upon.
	//
	// This is only ever useful if you do BIP-32 key derivation, or something similar.
	ChainKey []byte
	// VerificationShares is a map between parties and a commitment to their private share.
	//
	// This will later be used to verify the integrity of the signing protocol.
	VerificationShares map[party.ID]*curve.Secp256k1Point
}

// Clone creates a deep clone of this struct, and all the values contained inside
func (r *TaprootResult) Clone() *TaprootResult {
	publicKeyCopy := make([]byte, len(r.PublicKey))
	copy(publicKeyCopy, r.PublicKey)
	chainKeyCopy := make([]byte, len(r.ChainKey))
	copy(chainKeyCopy, r.ChainKey)
	verificationSharesCopy := make(map[party.ID]*curve.Secp256k1Point)
	for k, v := range r.VerificationShares {
		verificationSharesCopy[k] = v
	}
	return &TaprootResult{
		ID:                 r.ID,
		Threshold:          r.Threshold,
		PrivateShare:       curve.Secp256k1{}.NewScalar().Set(r.PrivateShare).(*curve.Secp256k1Scalar),
		PublicKey:          publicKeyCopy,
		ChainKey:           chainKeyCopy,
		VerificationShares: r.VerificationShares,
	}
}

// DeriveChild adjusts the shares to represent the derived public key at a certain index.
//
// This derivation works according to BIP-32, see:
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
//
// Note that to do this derivation, we interpret the Taproot key as an "old"
// ECDSA key, with the y coordinate byte set to 0x02. We also only look at the x
// coordinate of the derived public key, making sure that the corresponding secret
// key matches the version of this point with an even y coordinate.
func (r *TaprootResult) DeriveChild(i uint32) (*TaprootResult, error) {
	publicKey, err := curve.Secp256k1{}.LiftX(r.PublicKey)
	if err != nil {
		return nil, err
	}
	scalar, newChainKey, err := bip32.DeriveScalar(publicKey, r.ChainKey, i)
	if err != nil {
		return nil, err
	}
	newR := r.Clone()
	newVerificationShares := make(map[party.ID]curve.Point)
	for k, v := range newR.VerificationShares {
		newVerificationShares[k] = v
	}
	adjust(scalar, newR.PrivateShare, publicKey, newVerificationShares)
	for k, v := range newVerificationShares {
		newR.VerificationShares[k] = v.(*curve.Secp256k1Point)
	}
	// If our public key is odd, we need to negate our secret key, and everything
	// that entails. This means negating each secret share, and the corresponding
	// verification shares.
	if !publicKey.HasEvenY() {
		newR.PrivateShare.Negate()
		for _, v := range newR.VerificationShares {
			v.Negate()
		}
	}
	publicKeyBytes, _ := publicKey.MarshalBinary()
	newR.PublicKey = publicKeyBytes[1:]
	newR.ChainKey = newChainKey
	return newR, nil
}
