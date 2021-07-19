package refresh

import (
	"crypto/rand"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
)

type round1 struct {
	*round.Helper

	// SID = (𝔾, t,n,P₁,…,Pₙ)
	SID *session.sid

	// Self is the local data of the party executing the round
	Self    *LocalParty
	Parties map[party.ID]*LocalParty

	// PublicKey is the public key being refreshed. If keygen is being done, then it is the identity.
	PublicKey *curve.Point

	// Secret contains the previous secret ECDSA key share which is being refreshed
	// If a keygen is being performed, then it is 0.
	Secret *party.Secret

	// Threshold plus 1 is the minimum number of shares necessary to reconstruct the resulting secret
	Threshold int

	// PedersenSecret is λᵢ used to generate the Pedersen parameters
	PedersenSecret *big.Int

	// Decommitment of the 3rd message
	Decommitment hash.Decommitment // uᵢ

	// VSSSecret is fᵢ(X)
	VSSSecret *polynomial.Polynomial

	// SchnorrRand is an array to t+1 random aₗ ∈ 𝔽 used to compute Schnorr commitments of
	// the coefficients of the exponent polynomial Fᵢ(X)
	SchnorrRand *curve.Scalar
}

// ProcessMessage implements round.Round
func (r *round1) ProcessMessage(party.ID, round.Content) error {
	// In the first round, no messages are expected.
	return nil
}

// GenerateMessages implements round.Round
//
// - sample { aₗ }ₗ  <- 𝔽 for l = 0, …, t
// - set { Aᵢ = aₗ⋅G}ₗ for l = 0, …, t
// - sample Paillier pᵢ, qᵢ
// - sample Pedersen Nᵢ, Sᵢ, Tᵢ
// - sample fᵢ(X) <- 𝔽[X], deg(fᵢ) = t
//   - if keygen, fᵢ(0) = xᵢ (additive share of full ECDSA secret key)
//   - if refresh, fᵢ(0) = 0
// - compute Fᵢ(X) = fᵢ(X)⋅G
// - sample rhoᵢ <- {0,1}ᵏ
//   - if keygen, this is RIDᵢ
//   - if refresh, this is used to bind the zk proof to a random value
// - commit to message
func (r *round1) GenerateMessages(out chan<- *round.Message) error {
	// generate Paillier and Pedersen
	// TODO DEBUG
	var paillierSecret *paillier.SecretKey
	if r.SelfID() == "a" {
		paillierSecret = zk.ProverPaillierSecret
	} else if r.SelfID() == "b" {
		paillierSecret = zk.VerifierPaillierSecret
	} else {
		paillierSecret = paillier.NewSecretKey()
	}
	paillierPublic := paillierSecret.PublicKey
	pedersenPublic, pedersenSecret := paillierSecret.GeneratePedersen()

	// save our own share already so we are consistent with what we receive from others
	ownShare := r.VSSSecret.Evaluate(r.Self.ID.Scalar())

	// set Fᵢ(X) = fᵢ(X)•G
	vssPublic := polynomial.NewPolynomialExponent(r.VSSSecret)

	// generate Schnorr randomness and commitments
	schnorrRand, schnorrCommitment := sample.ScalarPointPair(rand.Reader)

	// Sample RIDᵢ
	var rid session.RID
	if _, err := rand.Read(rid[:]); err != nil {
		return ErrRound1SampleRho
	}

	// commit to data in message 2
	commitment, decommitment, err := r.HashForID(r.Self.ID).Commit(
		rid, vssPublic, schnorrCommitment, pedersenPublic)
	if err != nil {
		return ErrRound1Commit
	}

	// should be broadcast but we don't need that here
	msg := r.MarshalMessage(&Keygen2{Commitment: commitment}, r.OtherPartyIDs()...)
	if err = r.SendMessage(msg, out); err != nil {
		return err
	}

	r.Secret.Paillier = paillierSecret
	r.Self.Paillier = paillierPublic
	r.Self.Pedersen = pedersenPublic
	r.PedersenSecret = pedersenSecret

	r.Self.VSSPolynomial = vssPublic

	r.SchnorrRand = schnorrRand
	r.Self.SchnorrCommitments = schnorrCommitment

	r.Self.ShareReceived = ownShare
	r.Self.RID = rid
	r.Self.Commitment = commitment
	r.Decommitment = decommitment

	return nil
}

// Next implements round.Round
func (r *round1) Next() round.Round {
	return &round2{r, nil}
}

func (r *round1) MessageContent() round.Content {
	return &round.First{}
}
