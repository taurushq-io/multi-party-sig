package protocol

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

type Message struct {
	// SSID is a byte string which uniquely identifies the session this message belongs to.
	SSID []byte
	// From is the party.ID of the sender
	From party.ID
	// To is the intended recipient for this message. If To == "", then the message should be sent to all.
	To party.ID
	// Protocol identifies the protocol this message belongs to
	Protocol string
	// RoundNumber is the index of the round this message belongs to
	RoundNumber round.Number
	// Data is the actual content consumed by the round.
	Data []byte
	// Broadcast indicates whether this message should be reliably broadcast to all participants.
	Broadcast bool
	// BroadcastVerification is the hash of all messages broadcast by the parties,
	// and is included in all messages in the round following a broadcast round.
	BroadcastVerification []byte
}

// String implements fmt.Stringer.
func (m Message) String() string {
	return fmt.Sprintf("message: round %d, from: %s, to %v, protocol: %s", m.RoundNumber, m.From, m.To, m.Protocol)
}

// IsFor returns true if the message is intended for the designated party.
func (m Message) IsFor(id party.ID) bool {
	if m.From == id {
		return false
	}
	return m.To == "" || m.To == id
}

// Hash returns a 64 byte hash of the message content, including the headers.
// Can be used to produce a signature for the message.
func (m *Message) Hash() []byte {
	var broadcast byte
	if m.Broadcast {
		broadcast = 1
	}
	h := hash.New(
		hash.BytesWithDomain{TheDomain: "SSID", Bytes: m.SSID},
		m.From,
		m.To,
		hash.BytesWithDomain{TheDomain: "Protocol", Bytes: []byte(m.Protocol)},
		m.RoundNumber,
		hash.BytesWithDomain{TheDomain: "Content", Bytes: m.Data},
		hash.BytesWithDomain{TheDomain: "Broadcast", Bytes: []byte{broadcast}},
		hash.BytesWithDomain{TheDomain: "BroadcastVerification", Bytes: m.BroadcastVerification},
	)
	return h.Sum()
}

// marshallableMessage is a copy of message for the purpose of cbor marshalling.
//
// This is a workaround to use cbor's default marshalling for Message, all while providing
// a MarshalBinary method
type marshallableMessage struct {
	SSID                  []byte
	From                  party.ID
	To                    party.ID
	Protocol              string
	RoundNumber           round.Number
	Data                  []byte
	Broadcast             bool
	BroadcastVerification []byte
}

func (m *Message) toMarshallable() *marshallableMessage {
	return &marshallableMessage{
		SSID:                  m.SSID,
		From:                  m.From,
		To:                    m.To,
		Protocol:              m.Protocol,
		RoundNumber:           m.RoundNumber,
		Data:                  m.Data,
		Broadcast:             m.Broadcast,
		BroadcastVerification: m.BroadcastVerification,
	}
}

func (m *Message) MarshalBinary() ([]byte, error) {
	return cbor.Marshal(m.toMarshallable())
}

func (m *Message) UnmarshalBinary(data []byte) error {
	deserialized := m.toMarshallable()
	if err := cbor.Unmarshal(data, deserialized); err != nil {
		return nil
	}
	m.SSID = deserialized.SSID
	m.From = deserialized.From
	m.To = deserialized.To
	m.Protocol = deserialized.Protocol
	m.RoundNumber = deserialized.RoundNumber
	m.Data = deserialized.Data
	m.Broadcast = deserialized.Broadcast
	m.BroadcastVerification = deserialized.BroadcastVerification
	return nil
}
