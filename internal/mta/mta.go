package mta

import (
	"crypto/rand"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
	zkaffg "github.com/taurusgroup/multi-party-sig/pkg/zk/affg"
	zkaffp "github.com/taurusgroup/multi-party-sig/pkg/zk/affp"
)

// ProveAffG returns the necessary messages for the receiver of the
// h is a hash function initialized with the sender's ID.
// - senderSecretShare = aᵢ
// - senderSecretSharePoint = Aᵢ = aᵢ⋅G
// - receiverEncryptedShare = Encⱼ(bⱼ)
// The elements returned are :
// - Beta = β
// - D = (aⱼ ⊙ Bᵢ) ⊕ encᵢ(- β, s)
// - F = encⱼ(-β, r)
// - Proof = zkaffg proof of correct encryption.
func ProveAffG(group curve.Curve, h *hash.Hash,
	senderSecretShare *safenum.Int, senderSecretSharePoint curve.Point, receiverEncryptedShare *paillier.Ciphertext,
	sender *paillier.SecretKey, receiver *paillier.PublicKey, verifier *pedersen.Parameters) (Beta *safenum.Int, D, F *paillier.Ciphertext, Proof *zkaffg.Proof) {
	D, F, S, R, BetaNeg := newMta(senderSecretShare, receiverEncryptedShare, sender, receiver)
	Proof = zkaffg.NewProof(group, h, zkaffg.Public{
		Kv:       receiverEncryptedShare,
		Dv:       D,
		Fp:       F,
		Xp:       senderSecretSharePoint,
		Prover:   sender.PublicKey,
		Verifier: receiver,
		Aux:      verifier,
	}, zkaffg.Private{
		X: senderSecretShare,
		Y: BetaNeg,
		S: S,
		R: R,
	})
	Beta = BetaNeg.Neg(1)
	return
}

// ProveAffP generates a proof for the a specified verifier.
// This function is specified as to make clear which parameters must be input to zkaffg.
// h is a hash function initialized with the sender's ID.
// - senderSecretShare = aᵢ
// - senderSecretSharePoint = Aᵢ = Encᵢ(aᵢ)
// - receiverEncryptedShare = Encⱼ(bⱼ)
// The elements returned are :
// - Beta = β
// - D = (aⱼ ⊙ Bᵢ) ⊕ encᵢ(-β, s)
// - F = encⱼ(-β, r)
// - Proof = zkaffp proof of correct encryption.
func ProveAffP(group curve.Curve, h *hash.Hash,
	senderSecretShare *safenum.Int, senderEncryptedShare *paillier.Ciphertext, senderEncryptedShareNonce *safenum.Nat,
	receiverEncryptedShare *paillier.Ciphertext,
	sender *paillier.SecretKey, receiver *paillier.PublicKey, verifier *pedersen.Parameters) (Beta *safenum.Int, D, F *paillier.Ciphertext, Proof *zkaffp.Proof) {
	D, F, S, R, BetaNeg := newMta(senderSecretShare, receiverEncryptedShare, sender, receiver)
	Proof = zkaffp.NewProof(group, h, zkaffp.Public{
		Kv:       receiverEncryptedShare,
		Dv:       D,
		Fp:       F,
		Xp:       senderEncryptedShare,
		Prover:   sender.PublicKey,
		Verifier: receiver,
		Aux:      verifier,
	}, zkaffp.Private{
		X:  senderSecretShare,
		Y:  BetaNeg,
		S:  S,
		Rx: senderEncryptedShareNonce,
		R:  R,
	})
	Beta = BetaNeg.Neg(1)

	return
}

func newMta(senderSecretShare *safenum.Int, receiverEncryptedShare *paillier.Ciphertext,
	sender *paillier.SecretKey, receiver *paillier.PublicKey) (D, F *paillier.Ciphertext, S, R *safenum.Nat, BetaNeg *safenum.Int) {
	BetaNeg = sample.IntervalLPrime(rand.Reader)

	F, R = sender.Enc(BetaNeg) // F = encᵢ(-β, r)

	D, S = receiver.Enc(BetaNeg)
	tmp := receiverEncryptedShare.Clone().Mul(receiver, senderSecretShare) // tmp = aᵢ ⊙ Bⱼ
	D.Add(receiver, tmp)                                                   // D = encⱼ(-β;s) ⊕ (aᵢ ⊙ Bⱼ) = encⱼ(aᵢ•bⱼ-β)

	return
}
