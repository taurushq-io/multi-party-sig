package ecdsa

import (
	"encoding/binary"
	mrand "math/rand"
	"testing"

	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func generateShares(secret curve.Scalar, ids []party.ID) map[party.ID]curve.Scalar {
	group := secret.Curve()
	buf, _ := secret.MarshalBinary()
	seed := int64(binary.BigEndian.Uint64(buf))
	rand := mrand.New(mrand.NewSource(seed))
	sum := group.NewScalar()
	shares := make(map[party.ID]curve.Scalar)
	for i, id := range ids {
		if i == 0 {
			continue
		}
		share := sample.Scalar(rand, group)
		sum.Add(share)
		shares[id] = share
	}
	shares[ids[0]] = group.NewScalar().Set(secret).Sub(sum)
	return shares
}

func NewPreSignatures(group curve.Curve, N int) (x curve.Scalar, X curve.Point, preSignatures map[party.ID]*PreSignature) {
	rand := mrand.New(mrand.NewSource(0))

	partyIDs := test.PartyIDs(N)

	x = sample.Scalar(rand, group)
	X = x.ActOnBase()
	k := sample.Scalar(rand, group)
	kInv := group.NewScalar().Set(k).Invert()
	R := kInv.ActOnBase()
	// χ = x⋅k
	chi := group.NewScalar().Set(x).Mul(k)

	RBar := make(map[party.ID]curve.Point, N)
	S := make(map[party.ID]curve.Point, N)

	kShares := generateShares(k, partyIDs)
	chiShares := generateShares(chi, partyIDs)

	preSignatures = make(map[party.ID]*PreSignature, N)
	for _, id := range partyIDs {
		RBar[id] = group.NewScalar().Set(kShares[id]).Mul(kInv).ActOnBase()
		S[id] = chiShares[id].Act(R)
		preSignatures[id] = &PreSignature{
			R:        R,
			RBar:     party.NewPointMap(RBar),
			S:        party.NewPointMap(S),
			KShare:   kShares[id],
			ChiShare: chiShares[id],
		}
	}
	return
}

func TestPreSignature_Verify(t *testing.T) {
	N := 5
	group := curve.Secp256k1{}
	message := []byte("HELLO WORLD")
	_, X, preSignatures := NewPreSignatures(group, N)
	sigmaShares := make(map[party.ID]SignatureShare, N)
	for id, preSignature := range preSignatures {
		sigmaShares[id] = preSignature.SignatureShare(message)
	}
	for _, preSignature := range preSignatures {
		signature := preSignature.Signature(sigmaShares)
		if !signature.Verify(X, message) {
			t.Error("failed to validate signature")
		}
	}
}

func TestPreSignature_Fail(t *testing.T) {
	N := 5
	group := curve.Secp256k1{}
	message := []byte("HELLO WORLD")
	_, X, preSignatures := NewPreSignatures(group, N)
	sigmaShares := make(map[party.ID]SignatureShare, N)
	var culprit party.ID
	for id, preSignature := range preSignatures {
		if culprit == "" {
			culprit = id
		}
		sigmaShares[id] = preSignature.SignatureShare(message)
	}

	sigmaShares[culprit].Invert()

	for _, preSignature := range preSignatures {
		signature := preSignature.Signature(sigmaShares)
		if signature.Verify(X, message) {
			t.Error("signature should fail")
		}
		culprits := preSignature.VerifySignatureShares(sigmaShares, message)
		if len(culprits) != 1 || culprits[0] != culprit {
			t.Error("culprit should have been detected")
		}
	}
}
