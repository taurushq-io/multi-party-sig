package refresh

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type round2 struct {
	*round1
	// EchoHash = Hash(SSID, commitment₁, ..., commitmentₙ)
	EchoHash []byte
}

// ProcessMessage implements round.Round
//
// - store commitment Vⱼ
func (r *round2) ProcessMessage(msg round.Message) error {
	j := msg.GetHeader().From
	content := msg.(*Message).GetRefresh1()
	partyJ := r.LocalParties[j]

	partyJ.Commitment = content.Commitment

	return partyJ.AddMessage(msg)
}

// GenerateMessages implements round.Round
//
// Since we assume a simple P2P network, we use an extra round to "echo"
// the hash. Everybody sends a hash of all hashes.
//
// - send Hash(ssid, V₁, ..., Vₙ)
func (r *round2) GenerateMessages() ([]round.Message, error) {
	var err error
	// Broadcast the message we created in round1
	h := r.Hash.Clone()
	for _, partyID := range r.S.PartyIDs() {
		_, err = h.Write(r.LocalParties[partyID].Commitment)
		if err != nil {
			return nil, fmt.Errorf("refresh.round2.GenerateMessages(): write commitments to hash: %w", err)
		}
	}
	r.EchoHash, _ = h.ReadBytes(nil)

	return NewMessageRefresh2(r.SelfID, r.EchoHash), nil
}

// Finalize implements round.Round
func (r *round2) Finalize() (round.Round, error) {
	return &round3{
		round2: r,
	}, nil
}

func (r *round2) MessageType() round.MessageType {
	return MessageTypeRefresh1
}
