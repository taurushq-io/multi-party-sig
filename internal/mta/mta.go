package mta

import (
	"crypto/rand"
	"errors"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
	zkaffg "github.com/taurusgroup/multi-party-sig/pkg/zk/affg"
)

type Message struct {
	// Dij is Dᵢⱼ = (aⱼ ⊙ Bᵢ) ⊕ encᵢ(- βⱼᵢ, sⱼᵢ)
	Dij *paillier.Ciphertext
	// Fij is Fᵢⱼ = encⱼ(βⱼᵢ, rⱼᵢ)
	Fij   *paillier.Ciphertext
	Proof *zkaffg.Proof
}

// MtA holds the local data for the multiplicative-to-additive share conversion protocol.
// The sender and receiver are denoted by index i and j respectively, and we take the perspective of party i.
// i has share aᵢ and j has share bⱼ.
type MtA struct {
	// Dji = Dⱼᵢ = (aᵢ ⊙ Bⱼ) ⊕ encⱼ(- βᵢⱼ, sᵢⱼ)
	// Should be equal to encⱼ(aᵢ bⱼ - βᵢⱼ)
	Dji *paillier.Ciphertext
	// Fji = Fⱼᵢ = encᵢ(βᵢⱼ, rᵢⱼ)
	Fji *paillier.Ciphertext

	// S is the Paillier randomness sᵢⱼ for Dⱼᵢ = (aᵢ ⊙ Bⱼ) ⊕ encⱼ(- βᵢⱼ, sᵢⱼ)
	S *safenum.Nat
	// R is the Paillier randomness rᵢⱼ for Fⱼᵢ = encᵢ(-βᵢⱼ, rᵢⱼ)
	// Note, the paper says to use encᵢ(βᵢⱼ, rᵢⱼ), but it is probably a typo
	R *safenum.Nat
}

// New creates the MtA struct and returns the corresponding MtA message to be sent to i.
// Given the receiverEncryptedShare Bⱼ, and senderSecretShare aᵢ, sample βᵢⱼ and compute
// the encryption of the receiver's share.
func New(senderSecretShare *safenum.Int, receiverEncryptedShare *paillier.Ciphertext,
	sender *paillier.SecretKey, receiver *paillier.PublicKey) (*MtA, *safenum.Int) {

	BetaNeg := sample.IntervalLPrime(rand.Reader)

	// Fⱼᵢ = encᵢ(-βᵢⱼ, rᵢⱼ)
	Fji, r := sender.Enc(BetaNeg)

	// tempC = aᵢ ⊙ Bⱼ
	tempC := receiverEncryptedShare.Clone().Mul(receiver, senderSecretShare)

	// Dⱼᵢ = encⱼ(-βᵢⱼ) ⊕ (aᵢ ⊙ Bⱼ) = encⱼ(aᵢ•bⱼ-βᵢⱼ)
	Dji, s := receiver.Enc(BetaNeg)
	Dji.Add(receiver, tempC)

	Beta := BetaNeg.Neg(1)
	return &MtA{
		Dji: Dji,
		Fji: Fji,
		S:   s,
		R:   r,
	}, Beta
}

// ProofAffG generates a proof for the a specified verifier.
// This function is specified as to make clear which parameters must be input to zkaffg.
// h is a hash function initialized with the sender's ID.
// - senderSecretShare = aᵢ
// - senderSecretSharePoint = Aᵢ = aᵢ⋅G
// - receiverEncryptedShare = Encⱼ(bⱼ)
// The Message returned contains the encrypted share and a zk proof of correctness.
func (mta *MtA) ProofAffG(group curve.Curve, h *hash.Hash,
	senderSecretShare *safenum.Int, senderSecretSharePoint curve.Point, receiverEncryptedShare *paillier.Ciphertext, beta *safenum.Int,
	sender *paillier.SecretKey, receiver *paillier.PublicKey, verifier *pedersen.Parameters) *Message {
	zkPublic := zkaffg.Public{
		C:        receiverEncryptedShare,
		D:        mta.Dji,
		Y:        mta.Fji,
		X:        senderSecretSharePoint,
		Prover:   sender.PublicKey,
		Verifier: receiver,
		Aux:      verifier,
	}
	betaNeg := beta.Clone().Neg(1)
	zkPrivate := zkaffg.Private{
		X:    senderSecretShare,
		Y:    betaNeg,
		Rho:  mta.S,
		RhoY: mta.R,
	}
	proof := zkaffg.NewProof(group, h, zkPublic, zkPrivate)

	return &Message{
		Dij:   mta.Dji,
		Fij:   mta.Fji,
		Proof: proof,
	}
}

// VerifyAffG verifies the correctness of the received MtA message and stores the result.
// - receiverEncryptedShare = Encᵢ(bᵢ)
// - senderSharePoint = Aⱼ = aⱼ⋅G.
func (mta *MtA) VerifyAffG(h *hash.Hash,
	receiverEncryptedShare *paillier.Ciphertext, senderSharePoint curve.Point, msg *Message,
	sender *paillier.PublicKey, receiver *paillier.PublicKey, verifier *pedersen.Parameters) error {

	if msg.Dij == nil || msg.Fij == nil || msg.Proof == nil {
		return errors.New("sign.mta: message contains nil fields")
	}

	if !msg.Proof.Verify(h, zkaffg.Public{
		C:        receiverEncryptedShare,
		D:        msg.Dij,
		Y:        msg.Fij,
		X:        senderSharePoint,
		Prover:   sender,
		Verifier: receiver,
		Aux:      verifier,
	}) {
		return errors.New("mta: AffG proof failed")
	}

	return nil
}

// AlphaShare decrypts the appropriate field of the mta.Message given the receiver's private Paillier key.
func (msg *Message) AlphaShare(receiverPaillier *paillier.SecretKey) (*safenum.Int, error) {
	return receiverPaillier.Dec(msg.Dij)
}

func Empty(group curve.Curve) *Message {
	return &Message{
		Proof: zkaffg.Empty(group),
	}
}
