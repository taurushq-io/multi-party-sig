package refresh

import (
	"bytes"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type round3 struct {
	*round2
}

// ProcessMessage implements round.Round
//
// - verify Hash(SSID, V₁, …, Vₙ) against received hash
func (r *round3) ProcessMessage(msg round.Message) error {
	j := msg.GetHeader().From
	content := msg.(*Message).GetRefresh2()

	if !bytes.Equal(content.HashEcho, r.EchoHash) {
		return fmt.Errorf("refresh.round3.ProcessMessage(): party %s sent different hash than ours", j)
	}

	return nil // message is properly handled
}

// GenerateMessages implements round.Round
//
// - send all committed data
func (r *round3) GenerateMessages() ([]round.Message, error) {
	// Broadcast the message we created in round1
	return NewMessageRefresh3(r.SelfID, &Refresh3{
		Rho:                r.Self.Rho,
		VSSPolynomial:      r.Self.VSSPolynomial,
		SchnorrCommitments: r.Self.SchnorrCommitments,
		Pedersen:           r.Self.Public.Pedersen,
		Decommitment:       r.Decommitment,
	}), nil
}

// Next implements round.Round
func (r *round3) Next() round.Round {
	return &round4{
		round3: r,
	}
}

func (r *round3) MessageContent() round.Content {
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
