package keygen

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

var _ round.Round = (*round3)(nil)

type round3 struct {
	*round2
	// EchoHash = Hash(SSID, commitment₁, …, commitmentₙ)
	EchoHash []byte
}

// ProcessMessage implements round.Round.
//
// - verify Hash(SSID, V₁, …, Vₙ) against received hash.
func (r *round3) ProcessMessage(_ party.ID, content message.Content) error {
	body := content.(*Keygen3)

	if !bytes.Equal(body.HashEcho, r.EchoHash) {
		return ErrRound3EchoHash
	}
	return nil
}

// Finalize implements round.Round
//
// - send all committed data.
func (r *round3) Finalize(out chan<- *message.Message) (round.Round, error) {
	// Send the message we created in round1 to all
	msg := r.MarshalMessage(&Keygen4{
		RID:                r.RIDs[r.SelfID()],
		VSSPolynomial:      r.VSSPolynomials[r.SelfID()],
		SchnorrCommitments: r.SchnorrCommitments[r.SelfID()],
		N:                  r.N[r.SelfID()],
		S:                  r.S[r.SelfID()],
		T:                  r.T[r.SelfID()],
		Decommitment:       r.Decommitment,
	}, r.OtherPartyIDs()...)
	if err := r.SendMessage(msg, out); err != nil {
		return r, err
	}
	return &round4{round3: r}, nil
}

// MessageContent implements round.Round.
func (r *round3) MessageContent() message.Content { return &Keygen3{} }

// Validate implements message.Content.
func (m *Keygen3) Validate() error {
	if m == nil {
		return errors.New("keygen.round2: message is nil")
	}
	if l := len(m.HashEcho); l != params.HashBytes {
		return fmt.Errorf("keygen.round2: invalid echo hash length (got %d, expected %d)", l, params.HashBytes)
	}
	return nil
}

// RoundNumber implements message.Content.
func (m *Keygen3) RoundNumber() types.RoundNumber { return 3 }
