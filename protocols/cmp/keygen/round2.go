package keygen

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

type round2 struct {
	*round1
	// EchoHash = Hash(SSID, commitment₁, …, commitmentₙ)
	EchoHash []byte
}

// ProcessMessage implements round.Round
//
// - store commitment Vⱼ
func (r *round2) ProcessMessage(j party.ID, content message.Content) error {
	body := content.(*Keygen2)
	partyJ := r.Parties[j]

	partyJ.Commitment = body.Commitment
	return nil
}

// Finalize implements round.Round
//
// Since we assume a simple P2P network, we use an extra round to "echo"
// the hash. Everybody sends a hash of all hashes.
//
// - send Hash(ssid, V₁, …, Vₙ)
func (r *round2) Finalize(out chan<- *message.Message) (round.Round, error) {
	// Broadcast the message we created in round1
	h := r.Hash()
	for _, partyID := range r.PartyIDs() {
		_, _ = h.WriteAny(r.Parties[partyID].Commitment)
	}
	echoHash := h.ReadBytes(nil)

	// send to all
	msg := r.MarshalMessage(&Keygen3{HashEcho: echoHash}, r.OtherPartyIDs()...)
	if err := r.SendMessage(msg, out); err != nil {
		return r, err
	}

	r.EchoHash = echoHash
	return &round3{round2: r}, nil
}

// MessageContent implements round.Round
func (r *round2) MessageContent() message.Content { return &Keygen2{} }

// Validate implements message.Content
func (m *Keygen2) Validate() error {
	if m == nil {
		return errors.New("keygen.round1: message is nil")
	}
	if l := len(m.Commitment); l != params.HashBytes {
		return fmt.Errorf("keygen.round1: invalid commitment length (got %d, expected %d)", l, params.HashBytes)
	}
	return nil
}

// RoundNumber implements message.Content
func (m *Keygen2) RoundNumber() types.RoundNumber { return 2 }
