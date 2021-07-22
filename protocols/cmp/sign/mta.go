package sign

import (
	"crypto/rand"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	zkaffg "github.com/taurusgroup/cmp-ecdsa/pkg/zk/affg"
	"github.com/taurusgroup/cmp-ecdsa/protocols/cmp/keygen"
)

// MtA holds the local data for the multiplicative-to-additive share conversion protocol.
// The notation goes as follows:
// The Sender and Receiver are denoted by index i and j respectively, and we take the perspective of party i.
// i has share aᵢ and j has share bⱼ
type MtA struct {
	Sender, Receiver *keygen.Public

	// Secret is the senders share aᵢ
	Secret *curve.Scalar

	// Public is the sender's share as a public point Aᵢ = [aᵢ]G
	Public *curve.Point

	// K = Kⱼ is the encryption of the receiver's share bⱼ
	K *paillier.Ciphertext

	// D is Dⱼᵢ = (aᵢ ⊙ Kⱼ) ⊕ encⱼ(- βᵢⱼ, sᵢⱼ)
	// Should be equal to  encⱼ(aᵢ bⱼ - βᵢⱼ)
	D *paillier.Ciphertext
	// F is Fⱼᵢ = encᵢ(βᵢⱼ, rᵢⱼ)
	F *paillier.Ciphertext

	// Beta is βᵢⱼ
	Beta *curve.Scalar

	// S is the Paillier randomness sᵢⱼ for Dⱼᵢ = (aᵢ ⊙ Kⱼ) ⊕ encⱼ(- βᵢⱼ, sᵢⱼ)
	S *safenum.Nat
	// R is the Paillier randomness rᵢⱼ for Fⱼᵢ = encᵢ(-βᵢⱼ, rᵢⱼ)
	// Note, the paper says to use encᵢ(βᵢⱼ, rᵢⱼ), but it is probably a typo
	R *safenum.Nat

	// BetaNeg = - βᵢⱼ
	BetaNeg *safenum.Int
}

// NewMtA creates the MtA struct and returns the corresponding MtA message to be sent to i.
// - aᵢ, Aᵢ is i's secret share and corresponding group element
// - Kⱼ is the encryption of bⱼ sent by j in the previous round
func NewMtA(ai *curve.Scalar, Ai *curve.Point,
	Kj *paillier.Ciphertext,
	sender, receiver *keygen.Public) *MtA {

	beta := sample.IntervalLPrime(rand.Reader)

	betaNeg := beta.Clone().Neg(1)
	// Fⱼᵢ = encᵢ(-βᵢⱼ, rᵢⱼ)
	F, r := sender.Paillier.Enc(betaNeg)

	// tempC = aᵢ ⊙ Kⱼ
	tempC := Kj.Clone().Mul(receiver.Paillier, ai.Int())

	// Dⱼᵢ = encⱼ(-βᵢⱼ) ⊕ (aᵢ ⊙ Kⱼ) = encⱼ(aᵢ•kⱼ-βᵢⱼ)
	D, s := receiver.Paillier.Enc(betaNeg)
	D.Add(receiver.Paillier, tempC)

	mta := &MtA{
		Sender:   sender,
		Receiver: receiver,
		Secret:   ai,
		Public:   Ai,
		K:        Kj,
		D:        D,
		F:        F,
		Beta:     curve.NewScalarInt(beta),
		S:        s,
		R:        r,
		BetaNeg:  betaNeg,
	}
	return mta
}

// ProofAffG generates a proof for the a specified verifier. If the verifier is nil, then the receiver's (j)
// public parameters are used.
// This function is specified as to make clear which parameters must be input to zkaffg.
// h is a hash function initialized with i's ID
func (mta *MtA) ProofAffG(h *hash.Hash, verifier *keygen.Public) *MtAMessage {
	if verifier == nil {
		verifier = mta.Receiver
	}
	zkPublic := zkaffg.Public{
		C:        mta.K,
		D:        mta.D,
		Y:        mta.F,
		X:        mta.Public,
		Prover:   mta.Sender.Paillier,
		Verifier: mta.Receiver.Paillier,
		Aux:      verifier.Pedersen,
	}
	zkPrivate := zkaffg.Private{
		X:    mta.Secret.Int(),
		Y:    mta.BetaNeg,
		Rho:  mta.S,
		RhoY: mta.R,
	}
	proof := zkaffg.NewProof(h, zkPublic, zkPrivate)

	return &MtAMessage{
		D:     mta.D,
		F:     mta.F,
		Proof: proof,
	}
}

// VerifyAffG verifies the received MtA message where
// - Aj is the sender's public Aⱼ
// - Ki is the receiver's public Kᵢ
func (mta *MtAMessage) VerifyAffG(h *hash.Hash,
	Aj *curve.Point, Ki *paillier.Ciphertext,
	sender, receiver, verifier *keygen.Public) bool {
	if verifier == nil {
		verifier = receiver
	}
	return mta.Proof.Verify(h, zkaffg.Public{
		C:        Ki,
		D:        mta.D,
		Y:        mta.F,
		X:        Aj,
		Prover:   sender.Paillier,
		Verifier: receiver.Paillier,
		Aux:      verifier.Pedersen,
	})
}
