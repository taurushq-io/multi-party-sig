package refresh

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

type round3 struct {
	*round2
}

// ProcessMessage implements round.Round
//
// - verify Hash(SSID, V₁, …, Vₙ) against received hash
func (r *round3) ProcessMessage(from party.ID, content message.Content) error {
	body := content.(*Keygen3)

	if !bytes.Equal(body.HashEcho, r.EchoHash) {
		return ErrRound3EchoHash
	}
	return nil
}

// GenerateMessages implements round.Round
//
// - send all committed data
func (r *round3) GenerateMessages(out chan<- *message.Message) error {
	// Send the message we created in round1 to all
	msg := r.MarshalMessage(&Keygen4{
		RID:                r.Self.RID[:],
		VSSPolynomial:      r.Self.VSSPolynomial,
		SchnorrCommitments: r.Self.SchnorrCommitments,
		Pedersen:           r.Self.Pedersen,
		Decommitment:       r.Decommitment,
	}, r.OtherPartyIDs()...)
	if err := r.SendMessage(msg, out); err != nil {
		return err
	}
	return nil
}

// Next implements round.Round
func (r *round3) Next() round.Round {
	return &round4{
		round3: r,
	}
}

func (r *round3) MessageContent() message.Content {
	return &Keygen3{}
}

func (m *Keygen3) Validate() error {
	if m == nil {
		return errors.New("keygen.round2: message is nil")
	}
	if l := len(m.HashEcho); l != params.HashBytes {
		return fmt.Errorf("keygen.round2: invalid echo hash length (got %d, expected %d)", l, params.HashBytes)
	}
	return nil
}

func (m *Keygen3) RoundNumber() types.RoundNumber {
	return 3
}
