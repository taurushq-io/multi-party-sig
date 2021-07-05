package refresh

import (
	"errors"
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
	Public *party.Public

	// SchnorrCommitments is the Aⱼ used in the proof of knowledge in the last round
	SchnorrCommitments *curve.Point // Aⱼ

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

func Create(s session.Session) (round.Round, error) {
	var isDoingKeygen bool
	var name string
	switch s.(type) {
	case *session.Keygen:
		isDoingKeygen = true
		name = "keygen"
	case *session.Refresh:
		isDoingKeygen = false
		name = "refresh"
	default:
		return nil, errors.New("refresh.Create: s must be either *session.Keygen or *session.Refresh")
	}

	// Create round with a clone of the original secret
	base, err := round.NewBaseRound(s, name)
	if err != nil {
		return nil, fmt.Errorf("refresh.Create: %w", err)
	}

	parties := make(map[party.ID]*LocalParty, s.N())
	for _, idJ := range s.PartyIDs() {
		// Set the public data to a clone of the current data
		parties[idJ] = &LocalParty{
			Public: &party.Public{
				ID: idJ,
			},
		}
	}

	return &round1{
		BaseRound:     base,
		Self:          parties[base.SelfID],
		LocalParties:  parties,
		isDoingKeygen: isDoingKeygen,
	}, nil
}

func (r round1) ProtocolID() round.ProtocolID {
	return protocolID
}

// isKeygen is a convenience method for clarity
func (r round1) isKeygen() bool {
	return r.isDoingKeygen
}

func (r round1) isRefresh() bool {
	return !r.isDoingKeygen
}
