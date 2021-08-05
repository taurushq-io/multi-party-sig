package sign

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

// MtA holds the local data for the multiplicative-to-additive share conversion protocol.
// The sender and receiver are denoted by index i and j respectively, and we take the perspective of party i.
// i has share aᵢ and j has share bⱼ.
type MtA struct {
	i *paillier.SecretKey
	j *paillier.PublicKey

	// ai = aᵢ
	// i's share
	ai *curve.Scalar

	// Ai = Aᵢ = [aᵢ]•G
	// i's share as a public point
	Ai *curve.Point

	// Bj = Bⱼ
	// Encryption of the j's share bⱼ
	Bj *paillier.Ciphertext
	// Bi = Bᵢ
	// Encryption of the i's share bᵢ
	Bi *paillier.Ciphertext

	// Dji = Dⱼᵢ = (aᵢ ⊙ Kⱼ) ⊕ encⱼ(- βᵢⱼ, sᵢⱼ)
	// Should be equal to encⱼ(aᵢ bⱼ - βᵢⱼ)
	Dji *paillier.Ciphertext
	// Fji = Fⱼᵢ = encᵢ(βᵢⱼ, rᵢⱼ)
	Fji *paillier.Ciphertext

	// S is the Paillier randomness sᵢⱼ for Dⱼᵢ = (aᵢ ⊙ Kⱼ) ⊕ encⱼ(- βᵢⱼ, sᵢⱼ)
	S *safenum.Nat
	// R is the Paillier randomness rᵢⱼ for Fⱼᵢ = encᵢ(-βᵢⱼ, rᵢⱼ)
	// Note, the paper says to use encᵢ(βᵢⱼ, rᵢⱼ), but it is probably a typo
	R *safenum.Nat

	// BetaNeg = - βᵢⱼ
	BetaNeg *safenum.Int

	// Alpha = αᵢⱼ
	Alpha *safenum.Int
}

// NewMtA creates the MtA struct and returns the corresponding MtA message to be sent to i.
// - aᵢ, Aᵢ is i's secret share and corresponding group element
// - Bⱼ is the encryption of bⱼ sent by j in the previous round.
func NewMtA(ai *curve.Scalar,
	Ai *curve.Point,
	Bi, Bj *paillier.Ciphertext,
	i *paillier.SecretKey, j *paillier.PublicKey) *MtA {

	BetaNeg := sample.IntervalLPrime(rand.Reader)

	// Fⱼᵢ = encᵢ(-βᵢⱼ, rᵢⱼ)
	Fji, r := i.Enc(BetaNeg)

	// tempC = aᵢ ⊙ Bⱼ
	tempC := Bj.Clone().Mul(j, ai.Int())

	// Dⱼᵢ = encⱼ(-βᵢⱼ) ⊕ (aᵢ ⊙ Bⱼ) = encⱼ(aᵢ•bⱼ-βᵢⱼ)
	Dji, s := j.Enc(BetaNeg)
	Dji.Add(j, tempC)

	return &MtA{
		i:       i,
		j:       j,
		ai:      ai,
		Ai:      Ai,
		Bj:      Bj,
		Bi:      Bi,
		Dji:     Dji,
		Fji:     Fji,
		S:       s,
		R:       r,
		BetaNeg: BetaNeg,
	}
}

// ProofAffG generates a proof for the a specified verifier.
// This function is specified as to make clear which parameters must be input to zkaffg.
// h is a hash function initialized with i's ID.
func (mta *MtA) ProofAffG(h *hash.Hash, verifier *pedersen.Parameters) *MtAMessage {
	zkPublic := zkaffg.Public{
		C:        mta.Bj,
		D:        mta.Dji,
		Y:        mta.Fji,
		X:        mta.Ai,
		Prover:   mta.i.PublicKey,
		Verifier: mta.j,
		Aux:      verifier,
	}
	zkPrivate := zkaffg.Private{
		X:    mta.ai.Int(),
		Y:    mta.BetaNeg,
		Rho:  mta.S,
		RhoY: mta.R,
	}
	proof := zkaffg.NewProof(h, zkPublic, zkPrivate)

	return &MtAMessage{
		Dij:   mta.Dji,
		Fij:   mta.Fji,
		Proof: proof,
	}
}

// Input verifies the received MtA message and stores the result.
// Aj is the public point corresponding to j's secret.
func (mta *MtA) Input(h *hash.Hash, verifier *pedersen.Parameters, msg *MtAMessage, Aj *curve.Point) error {

	if msg.Dij == nil || msg.Fij == nil || msg.Proof == nil {
		return errors.New("sign.mta: message contains nil fields")
	}

	if !msg.Proof.Verify(h, zkaffg.Public{
		C:        mta.Bi,
		D:        msg.Dij,
		Y:        msg.Fij,
		X:        Aj,
		Prover:   mta.j,
		Verifier: mta.i.PublicKey,
		Aux:      verifier,
	}) {
		return errors.New("mta: AffG proof failed")
	}

	decryptedShare, err := mta.i.Dec(msg.Dij)
	if err != nil {
		return err
	}
	mta.Alpha = decryptedShare
	return nil
}

// Share returns the Scalar γᵢ = αᵢⱼ + βᵢⱼ.
func (mta *MtA) Share() *curve.Scalar {
	if mta.Alpha == nil || mta.BetaNeg == nil {
		return nil
	}
	share := mta.BetaNeg.Clone().Neg(1)
	share.Add(share, mta.Alpha, -1)
	return curve.NewScalarInt(share)
}
