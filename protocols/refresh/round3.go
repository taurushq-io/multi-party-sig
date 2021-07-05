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

// Finalize implements round.Round
func (r *round3) Finalize() (round.Round, error) {
	r.Next()
	return &round4{
		round3: r,
	}, nil
}

func (r *round3) ExpectedMessageID() round.MessageID {
	return MessageTypeRefresh2
}
