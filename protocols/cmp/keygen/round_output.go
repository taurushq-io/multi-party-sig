package keygen

import (
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/message"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/types"
	sch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
)

var _ round.Round = (*output)(nil)

type output struct {
	*round4
	UpdatedConfig *Config
}

type KeygenOutput struct {
	// SchnorrResponse is the Schnorr proof of knowledge of the new secret share
	SchnorrResponse *sch.Response
}

// VerifyMessage implements round.Round.
//
// - verify all Schnorr proof for the new ecdsa share.
func (r *output) VerifyMessage(from party.ID, _ party.ID, content message.Content) error {
	body, ok := content.(*KeygenOutput)
	if !ok || body == nil {
		return message.ErrInvalidContent
	}

	if body.SchnorrResponse == nil {
		return message.ErrNilContent
	}

	if !body.SchnorrResponse.Verify(r.HashForID(from),
		r.UpdatedConfig.Public[from].ECDSA,
		r.SchnorrCommitments[from]) {
		return ErrRoundOutputZKSch
	}
	return nil
}

// StoreMessage implements round.Round.
func (r *output) StoreMessage(party.ID, message.Content) error { return nil }

// Finalize implements round.Round.
func (r *output) Finalize(chan<- *message.Message) (round.Round, error) {
	return &round.Output{Result: &Result{
		Config: r.UpdatedConfig,
	}}, nil
}

// MessageContent implements round.Round.
func (r *output) MessageContent() message.Content { return &KeygenOutput{} }

// RoundNumber implements message.Content.
func (m *KeygenOutput) RoundNumber() types.RoundNumber { return 6 }
