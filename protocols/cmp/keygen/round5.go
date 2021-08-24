package keygen

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	sch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/config"
)

var _ round.Round = (*round5)(nil)

type round5 struct {
	*round4
	UpdatedConfig *config.Config
}

type message5 struct {
	// SchnorrResponse is the Schnorr proof of knowledge of the new secret share
	SchnorrResponse *sch.Response
}

// VerifyMessage implements round.Round.
//
// - verify all Schnorr proof for the new ecdsa share.
func (r *round5) VerifyMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*message5)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.SchnorrResponse == nil {
		return round.ErrNilFields
	}

	if !body.SchnorrResponse.Verify(r.HashForID(from),
		r.UpdatedConfig.Public[from].ECDSA,
		r.SchnorrCommitments[from]) {
		return errors.New("failed to validate schnorr proof for received share")
	}
	return nil
}

// StoreMessage implements round.Round.
func (r *round5) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
func (r *round5) Finalize(chan<- *round.Message) (round.Session, error) {
	return r.ResultRound(r.UpdatedConfig), nil
}

// MessageContent implements round.Round.
func (round5) MessageContent() round.Content { return &message5{} }

// Number implements round.Round.
func (round5) Number() round.Number { return 5 }

// Init implements round.Content.
func (m *message5) Init(group curve.Curve) {
	m.SchnorrResponse = sch.EmptyResponse(group)
}
