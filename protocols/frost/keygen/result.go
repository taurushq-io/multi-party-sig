package keygen

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/internal/bip32"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/taproot"
)

func adjust(with *curve.Scalar, priv *curve.Scalar, pub *curve.Point, pubShares map[party.ID]*curve.Point) {
	priv.Add(priv, with)
	withG := curve.NewIdentityPoint().ScalarBaseMult(with)
	pub.Add(pub, withG)
	for _, v := range pubShares {
		v.Add(v, withG)
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
	PrivateShare *curve.Scalar
	// PublicKey is the shared public key for this consortium of signers.
	//
	// This key can be used to verify signatures produced by the consortium.
	PublicKey *curve.Point
	// ChainKey is the additional randomness we've agreed upon.
	//
	// This is only ever useful if you do BIP-32 key derivation, or something similar.
	ChainKey []byte
	// VerificationShares is a map between parties and a commitment to their private share.
	//
	// This will later be used to verify the integrity of the signing protocol.
	VerificationShares map[party.ID]*curve.Point
}

// Clone creates a deep clone of this struct, and all the values contained inside
func (r *Result) Clone() *Result {
	chainKeyCopy := make([]byte, len(r.ChainKey))
	copy(chainKeyCopy, r.ChainKey)
	verificationSharesCopy := make(map[party.ID]*curve.Point)
	for k, v := range r.VerificationShares {
		verificationSharesCopy[k] = curve.NewIdentityPoint().Set(v)
	}
	return &Result{
		ID:                 r.ID,
		Threshold:          r.Threshold,
		PrivateShare:       curve.NewScalar().Set(r.PrivateShare),
		PublicKey:          curve.NewIdentityPoint().Set(r.PublicKey),
		ChainKey:           chainKeyCopy,
		VerificationShares: verificationSharesCopy,
	}
}

// DeriveChild adjusts the shares to represent the derived public key at a certain index.
//
// This derivation works according to BIP-32, see:
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
func (r *Result) DeriveChild(i uint32) (*Result, error) {
	scalar, newChainKey, err := bip32.DeriveScalar(r.PublicKey, r.ChainKey, i)
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
	PrivateShare *curve.Scalar
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
	VerificationShares map[party.ID]*curve.Point
}

// Clone creates a deep clone of this struct, and all the values contained inside
func (r *TaprootResult) Clone() *TaprootResult {
	publicKeyCopy := make([]byte, len(r.PublicKey))
	copy(publicKeyCopy, r.PublicKey)
	chainKeyCopy := make([]byte, len(r.ChainKey))
	copy(chainKeyCopy, r.ChainKey)
	verificationSharesCopy := make(map[party.ID]*curve.Point)
	for k, v := range r.VerificationShares {
		verificationSharesCopy[k] = curve.NewIdentityPoint().Set(v)
	}
	return &TaprootResult{
		ID:                 r.ID,
		Threshold:          r.Threshold,
		PrivateShare:       curve.NewScalar().Set(r.PrivateShare),
		PublicKey:          publicKeyCopy,
		ChainKey:           chainKeyCopy,
		VerificationShares: verificationSharesCopy,
	}
}

// ErrTaprootDeriveUnluckyIndex indicates that an unlucky index was encountered when deriving a key
//
// This happens quite a bit more often with Taproot, and simply indicates that a different
// index should be tried, since this index cannot generate a valid key
var ErrTaprootDeriveUnluckyIndex = errors.New("unlucky index when deriving Taproot key")

// DeriveChild adjusts the shares to represent the derived public key at a certain index.
//
// This derivation works according to BIP-32, see:
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
//
// Note that to do this derivation, we interpret the Taproot key as an "old"
// ECDSA key, with the y coordinate byte set to 0x02. Because of this, key derivation
// will also fail more often, so it's imperative to check that this function hasn't
// produced ErrTaprootDeriveUnluckyIndex. This error indicates that trying again might
// succeed with a different index
func (r *TaprootResult) DeriveChild(i uint32) (*TaprootResult, error) {
	publicKey, err := curve.LiftX(r.PublicKey)
	if err != nil {
		return nil, err
	}
	scalar, newChainKey, err := bip32.DeriveScalar(publicKey, r.ChainKey, i)
	if err != nil {
		return nil, err
	}
	newR := r.Clone()
	adjust(scalar, newR.PrivateShare, publicKey, newR.VerificationShares)
	// Need to make sure that our new public key has the right format, otherwise
	// we're going to run into trouble later
	if !publicKey.HasEvenY() {
		return nil, ErrTaprootDeriveUnluckyIndex
	}
	newR.PublicKey = publicKey.XBytes()[:]
	newR.ChainKey = newChainKey
	return newR, nil
}
