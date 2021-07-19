package round

import (
	"errors"
	"sync"

	any "github.com/gogo/protobuf/types"
	"github.com/taurusgroup/cmp-ecdsa/internal/writer"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

// Helper implements protocol.Info and can therefore be embedded in the first round of a protocol
// in order to satisfy the Round interface.
type Helper struct {
	// protocolID is string identifier for this protocol
	protocolID types.ProtocolID
	// finalRoundNumber is the number of rounds before the output round.
	finalRoundNumber types.RoundNumber
	// selfID is this party's ID.
	selfID party.ID
	// partyIDs is a sorted slice of participating parties in this protocol.
	// otherPartyIDs is the same as partyIDs without selfID
	partyIDs, otherPartyIDs party.IDSlice
	// ssid the unique identifier for this protocol execution
	ssid []byte

	mtx  sync.Mutex
	hash *hash.Hash
}

func NewHelper(
	protocolID types.ProtocolID,
	finalRoundNumber types.RoundNumber,
	selfID party.ID,
	partyIDs party.IDSlice,
	hash *hash.Hash,
) *Helper {
	return &Helper{
		protocolID:       protocolID,
		finalRoundNumber: finalRoundNumber,
		selfID:           selfID,
		partyIDs:         partyIDs,
		otherPartyIDs:    partyIDs.Remove(selfID),
		ssid:             hash.Clone().ReadBytes(nil),
		hash:             hash,
	}
}

func (r *Helper) Hash() *hash.Hash {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	return r.hash.Clone()
}

// HashForID returns a clone of the hash.Hash for this session, initialized with the given id
func (r *Helper) HashForID(id party.ID) *hash.Hash {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	h := r.hash.Clone()
	if id != "" {
		_, _ = h.WriteAny(id)
	}
	return h
}

// UpdateHashState writes additional data to the hash state.
func (r *Helper) UpdateHashState(value writer.WriterToWithDomain) {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	_, _ = r.hash.WriteAny(value)
}

// MarshalMessage returns a Message for the given content, and sets the headers appropriately.
// If to is empty, then the message will be interpreted as "Broadcast".
// For "Send to all" behavior, the full list of parties can be given.
// It panics if the content is not able to be marshalled.
func (h *Helper) MarshalMessage(content message.Content, to ...party.ID) *message.Message {
	c, err := any.MarshalAny(content)
	if err == nil {
		return &message.Message{
			SSID:        h.ssid,
			From:        h.selfID,
			To:          to,
			Protocol:    h.protocolID,
			RoundNumber: content.RoundNumber(), // message is intended for the next round
			Content:     c,
		}
	}
	panic("protocol: unable to marshal message content")
}

func (h *Helper) SendMessage(msg *message.Message, out chan<- *message.Message) error {
	select {
	case out <- msg:
		return nil
	default:
		return errors.New("messages out channel is full")
	}
}

// ProtocolID is string identifier for this protocol
func (h *Helper) ProtocolID() types.ProtocolID { return h.protocolID }

// FinalRoundNumber is the number of rounds before the output round.
func (h *Helper) FinalRoundNumber() types.RoundNumber { return h.finalRoundNumber }

// SelfID is this party's ID.
func (h *Helper) SelfID() party.ID { return h.selfID }

// PartyIDs is a sorted slice of participating parties in this protocol.
func (h *Helper) PartyIDs() party.IDSlice { return h.partyIDs }

// SSID the unique identifier for this protocol execution
func (h *Helper) SSID() []byte { return h.ssid }

// N returns the number of participants.
func (h *Helper) N() int { return len(h.partyIDs) }

// OtherPartyIDs returns a sorted list of parties that does not contain SelfID
func (h *Helper) OtherPartyIDs() party.IDSlice {
	return h.partyIDs.Remove(h.selfID)
}
