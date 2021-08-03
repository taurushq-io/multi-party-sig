package keygen

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/internal/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol/types"
)

var _ round.Round = (*output)(nil)

type output struct {
	*round4
	UpdatedConfig *Config
}

// ProcessMessage implements round.Round.
//
// - verify all Schnorr proof for the new ecdsa share.
func (r *output) ProcessMessage(j party.ID, content message.Content) error {
	body := content.(*KeygenOutput)

	if !body.SchnorrResponse.Verify(r.HashForID(j),
		r.UpdatedConfig.Public[j].ECDSA,
		r.SchnorrCommitments[j]) {
		return ErrRoundOutputZKSch
	}
	return nil
}

// Finalize implements round.Round.
func (r *output) Finalize(chan<- *message.Message) (round.Round, error) {
	return &round.Output{Result: &Result{
		Config: r.UpdatedConfig,
	}}, nil
}

// MessageContent implements round.Round.
func (r *output) MessageContent() message.Content { return &KeygenOutput{} }

// Validate implements message.Content.
func (m *KeygenOutput) Validate() error {
	if m == nil {
		return errors.New("keygen.output: message is nil")
	}
	if m.SchnorrResponse == nil {
		return errors.New("keygen.output: sch proof is nil")
	}
	return nil
}

// RoundNumber implements message.Content.
func (m *KeygenOutput) RoundNumber() types.RoundNumber { return 6 }
