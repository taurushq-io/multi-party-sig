package refresh

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type round1 struct {
	*round.BaseRound

	Self         *LocalParty
	LocalParties map[party.ID]*LocalParty

	// PaillierSecret is the newly generated Paillier key
	PaillierSecret *paillier.SecretKey
	// PedersenSecret is λᵢ used to generate the Pedersen parameters
	PedersenSecret *big.Int

	// Decommitment of the 3rd message
	Decommitment hash.Decommitment // uᵢ

	// VSSSecret is fᵢ(X)
	VSSSecret *polynomial.Polynomial

	// SchnorrRand is an array to t+1 random aₗ ∈ 𝔽 used to compute Schnorr commitments of
	// the coefficients of the exponent polynomial Fᵢ(X)
	SchnorrRand *curve.Scalar

	isDoingKeygen bool
}

// ProcessMessage implements round.Round
func (r *round1) ProcessMessage(round.Message) error {
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
func (r *round1) GenerateMessages() ([]round.Message, error) {
	var err error

	// generate Paillier and Pedersen
	skPaillier := paillier.NewSecretKey()
	r.Self.Public.Pedersen, r.PedersenSecret = skPaillier.GeneratePedersen()
	r.PaillierSecret = skPaillier
	r.Self.Public.Paillier = skPaillier.PublicKey

	// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = constant
	// if keygen then constant = secret, otherwise it is 0 (nil)
	var constant *curve.Scalar
	if r.isKeygen() {
		constant = sample.Scalar(rand.Reader)
	}
	r.VSSSecret = polynomial.NewPolynomial(r.S.Threshold(), constant)

	// save our own share already so we are consistent with what we receive from others
	r.Self.ShareReceived = r.VSSSecret.Evaluate(r.SelfID.Scalar())

	// set Fᵢ(X) = fᵢ(X)•G
	r.Self.VSSPolynomial = polynomial.NewPolynomialExponent(r.VSSSecret)

	// generate Schnorr randomness and commitments
	r.SchnorrRand, r.Self.SchnorrCommitments = sample.ScalarPointPair(rand.Reader)

	// Sample ρᵢ
	r.Self.Rho = make([]byte, params.SecBytes)
	if _, err = rand.Read(r.Self.Rho); err != nil {
		return nil, fmt.Errorf("refresh.round1.GenerateMessages(): sample Rho: %w", err)
	}

	// commit to data in message 2
	r.Self.Commitment, r.Decommitment, err = r.Hash.Commit(r.SelfID,
		r.Self.Rho, r.Self.VSSPolynomial, r.Self.SchnorrCommitments, r.Self.Public.Pedersen)
	if err != nil {
		return nil, fmt.Errorf("refresh.round1.GenerateMessages(): commit: %w", err)
	}

	return NewMessageRefresh1(r.SelfID, r.Self.Commitment), nil
}

// Next implements round.Round
func (r *round1) Next() round.Round {
	return &round2{r, nil}
}

func (r *round1) MessageContent() round.Content {
	return &round.First{}
}
