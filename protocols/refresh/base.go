package refresh

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
)

var (
	_ round.Round = (*round1)(nil)
	_ round.Round = (*round2)(nil)
	_ round.Round = (*round3)(nil)
	_ round.Round = (*round4)(nil)
	_ round.Round = (*output)(nil)
)

// LocalParty is the state we store for a remote party.
// The messages are embedded to make access to the attributes easier.
type LocalParty struct {
	*round.Party

	Public *party.Public

	// VSSCommitments are the Schnorr commitments to the polynomial in the exponent
	// for VSS
	VSSCommitments []curve.Point // Aⱼ

	// Commitment = H(msg3 ∥ Decommitment)
	Commitment hash.Commitment

	// Rho = ρⱼ
	// if keygen, then this is RIDⱼ
	Rho []byte

	// VSSPolynomial = Fⱼ(X) = fⱼ(X)•G
	VSSPolynomial *polynomial.Exponent

	// ShareReceived = xʲᵢ is the share received from party j
	ShareReceived *curve.Scalar
}

func NewRound(session session.Session) (*round1, error) {
	// Create round with a clone of the original secret
	base, err := round.NewBaseRound(session)
	if err != nil {
		return nil, fmt.Errorf("refresh.NewRound: %w", err)
	}

	parties := make(map[party.ID]*LocalParty, session.N())
	for _, idJ := range session.PartyIDs() {
		// Set the public data to a clone of the current data
		parties[idJ] = &LocalParty{
			Party: round.NewBaseParty(idJ),
			Public: &party.Public{
				ID: idJ,
			},
		}
	}

	return &round1{
		BaseRound:     base,
		Self:          parties[base.SelfID],
		LocalParties:  parties,
		isDoingKeygen: !session.Secret().KeygenDone(),
	}, nil
}

// isKeygen is a convenience method for clarity
func (r round1) isKeygen() bool {
	return r.isDoingKeygen
}

func (r round1) isRefresh() bool {
	return !r.isDoingKeygen
}
