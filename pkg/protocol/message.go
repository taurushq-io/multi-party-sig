package protocol

import (
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type Message struct {
	// SSID is a byte string which uniquely identifies the session this message belongs to.
	SSID []byte
	// From is the party.ID of the sender
	From party.ID
	// To is a list of intended recipients for this message.
	// If To == nil, then the message should be interpreted as a broadcast message.
	To party.ID
	// Protocol identifies the protocol this message belongs to
	Protocol string
	// RoundNumber is the index of the round this message belongs to
	RoundNumber round.Number
	// Data is the actual content consumed by the round.
	Data []byte
	// Signature TODO
	Signature []byte
}

// String implements fmt.Stringer.
func (m Message) String() string {
	return fmt.Sprintf("message: round %d, from: %s, to %v, protocol: %s", m.RoundNumber, m.From, m.To, m.Protocol)
}

// Broadcast returns true if the message should be reliably broadcast to all participants in the protocol.
func (m Message) Broadcast() bool {
	return m.To == ""
}

// IsFor returns true if the message is intended for the designated party.
func (m Message) IsFor(id party.ID) bool {
	if m.From == id {
		return false
	}
	return m.To == "" || m.To == id
}

// Hash returns a 64 byte slice of the message content, including the headers.
// Can be used to produce a signature for the message.
func (m Message) Hash() []byte {
	h := hash.New(
		hash.BytesWithDomain{TheDomain: "SSID", Bytes: m.SSID},
		m.From,
		m.To,
		hash.BytesWithDomain{TheDomain: "Protocol", Bytes: []byte(m.Protocol)},
		m.RoundNumber,
		hash.BytesWithDomain{TheDomain: "Content", Bytes: m.Data},
	)
	return h.Sum()
}
