package keygen

import (
	"crypto/rand"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

var _ round.Round = (*round1)(nil)

type round1 struct {
	*round.Helper

	// Threshold is the integer t which defines the maximum number of corruptions tolerated for this config.
	Threshold int

	// PreviousSecretECDSA = sk'ᵢ
	// Contains the previous secret ECDSA key share which is being refreshed
	// Keygen:  sk'ᵢ = 0
	// Refresh: sk'ᵢ = sk'ᵢ
	PreviousSecretECDSA *curve.Scalar

	// PreviousPublicKey = pk'
	// Public key being refreshed.
	// Keygen:  pk' = ∞
	// Refresh: pk' = pk'
	PreviousPublicKey *curve.Point

	// PreviousPublicSharesECDSA[j] = pk'ⱼ
	// Keygen:  pk'ⱼ = ∞
	// Refresh: pk'ⱼ = pk'ⱼ
	PreviousPublicSharesECDSA map[party.ID]*curve.Point

	// VSSSecret = fᵢ(X)
	// Polynomial from which the new secret shares are computed.
	// Keygen:  fᵢ(0) = xⁱ
	// Refresh: fᵢ(0) = 0
	VSSSecret *polynomial.Polynomial
}

// ProcessMessage implements round.Round.
func (r *round1) ProcessMessage(party.ID, message.Content) error { return nil }

// Finalize implements round.Round
//
// - sample Paillier (pᵢ, qᵢ)
// - sample Pedersen Nᵢ, sᵢ, tᵢ
// - sample aᵢ  <- 𝔽
// - set Aᵢ = aᵢ⋅G
// - compute Fᵢ(X) = fᵢ(X)⋅G
// - sample ridᵢ <- {0,1}ᵏ
// - commit to message.
func (r *round1) Finalize(out chan<- *message.Message) (round.Round, error) {
	// generate Paillier and Pedersen
	PaillierSecret := paillier.NewSecretKey()
	SelfPaillierPublic := PaillierSecret.PublicKey
	SelfPedersenPublic, PedersenSecret := PaillierSecret.GeneratePedersen()

	// save our own share already so we are consistent with what we receive from others
	SelfShare := r.VSSSecret.Evaluate(r.SelfID().Scalar())

	// set Fᵢ(X) = fᵢ(X)•G
	SelfVSSPolynomial := polynomial.NewPolynomialExponent(r.VSSSecret)

	// generate Schnorr randomness and commitments
	SchnorrRand, SelfSchnorrCommitment := sample.ScalarPointPair(rand.Reader)

	// Sample RIDᵢ
	SelfRID := newRID()
	if _, err := rand.Read(SelfRID[:]); err != nil {
		return r, ErrRound1SampleRho
	}

	// commit to data in message 2
	SelfCommitment, Decommitment, err := r.HashForID(r.SelfID()).Commit(
		SelfRID, SelfVSSPolynomial, SelfSchnorrCommitment, SelfPedersenPublic)
	if err != nil {
		return r, ErrRound1Commit
	}

	// should be broadcast but we don't need that here
	msg := r.MarshalMessage(&Keygen2{Commitment: SelfCommitment}, r.OtherPartyIDs()...)
	if err = r.SendMessage(msg, out); err != nil {
		return r, err
	}

	return &round2{
		round1:             r,
		VSSPolynomials:     map[party.ID]*polynomial.Exponent{r.SelfID(): SelfVSSPolynomial},
		SchnorrCommitments: map[party.ID]*curve.Point{r.SelfID(): SelfSchnorrCommitment},
		Commitments:        map[party.ID]hash.Commitment{r.SelfID(): SelfCommitment},
		RIDs:               map[party.ID]RID{r.SelfID(): SelfRID},
		ShareReceived:      map[party.ID]*curve.Scalar{r.SelfID(): SelfShare},
		PaillierPublic:     map[party.ID]*paillier.PublicKey{r.SelfID(): SelfPaillierPublic},
		N:                  map[party.ID]*big.Int{r.SelfID(): SelfPedersenPublic.N()},
		S:                  map[party.ID]*big.Int{r.SelfID(): SelfPedersenPublic.S()},
		T:                  map[party.ID]*big.Int{r.SelfID(): SelfPedersenPublic.T()},
		PaillierSecret:     PaillierSecret,
		PedersenSecret:     PedersenSecret,
		SchnorrRand:        SchnorrRand,
		Decommitment:       Decommitment,
	}, nil
}

// MessageContent implements round.Round..
func (r *round1) MessageContent() message.Content { return &message.First{} }
