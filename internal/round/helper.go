package round

import (
	"errors"
	"sync"

	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// Helper implements protocol.Info and can therefore be embedded in the first round of a protocol
// in order to satisfy the Round interface.
type Helper struct {
	// protocolID is string identifier for this protocol
	protocolID string
	// finalRoundNumber is the number of rounds before the output round.
	finalRoundNumber Number
	// selfID is this party's ID.
	selfID party.ID
	// partyIDs is a sorted slice of participating parties in this protocol.
	// otherPartyIDs is the same as partyIDs without selfID
	partyIDs, otherPartyIDs party.IDSlice

	// group for signature
	group curve.Curve

	// ssid the unique identifier for this protocol execution
	ssid []byte

	hash *hash.Hash

	mtx sync.Mutex
}

func NewHelper(protocolID string, group curve.Curve, finalRoundNumber Number,
	selfID party.ID, partyIDs party.IDSlice,
	auxInfo ...hash.WriterToWithDomain) (*Helper, error) {

	if !partyIDs.Valid() {
		return nil, errors.New("helper: partyIDs invalid")
	}

	// verify our ID is present
	if !partyIDs.Contains(selfID) {
		return nil, errors.New("helper: selfID not included in partyIDs")
	}

	h := hashFromSID(protocolID, group, partyIDs, auxInfo...)

	return &Helper{
		protocolID:       protocolID,
		finalRoundNumber: finalRoundNumber,
		selfID:           selfID,
		partyIDs:         partyIDs,
		otherPartyIDs:    partyIDs.Remove(selfID),
		group:            group,
		ssid:             h.Clone().Sum(),
		hash:             h,
	}, nil
}

// hashFromSID returns a new hash.Hash function initialized with the full SSID.
// It assumes that the state is in a correct, and can panic if it is not.
// Calling hash.Sum() on the resulting hash function returns the hash of the SSID.
// It computes
// - Hash(𝔾, n, P₁, …, Pₙ, auxInfo}.
func hashFromSID(protocolID string, group curve.Curve, partyIDs party.IDSlice, auxInfo ...hash.WriterToWithDomain) *hash.Hash {
	// sid = protocolID 𝔾, n, P₁, …, Pₙ
	sid := []hash.WriterToWithDomain{
		&hash.BytesWithDomain{
			TheDomain: "Protocol ID",
			Bytes:     []byte(protocolID),
		},
		&hash.BytesWithDomain{
			TheDomain: "Group Name",
			Bytes:     []byte(group.Name()),
		},
		partyIDs,
	}
	h := hash.New(append(sid, auxInfo...)...)
	return h
}

// Hash returns copy of the hash function of this protocol execution.
func (h *Helper) Hash() *hash.Hash {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	return h.hash.Clone()
}

// HashForID returns a clone of the hash.Hash for this session, initialized with the given id.
func (h *Helper) HashForID(id party.ID) *hash.Hash {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	cloned := h.hash.Clone()
	if id != "" {
		_ = cloned.WriteAny(id)
	}
	return cloned
}

// UpdateHashState writes additional data to the hash state.
func (h *Helper) UpdateHashState(value hash.WriterToWithDomain) {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	_ = h.hash.WriteAny(value)
}

// SendMessage returns a message.Message for the given content with the appropriate headers.
// If to is empty, then the message will be interpreted as "Broadcast".
// For "Send to all" behavior, the full list of parties can be given.
// It panics if the content is not able to be marshalled.
// SendMessage is a convenience function for all rounds that attempts to send the message to the channel.
// If the channel is full or closed, an error is returned.
func (h *Helper) SendMessage(out chan<- *Message, content Content, to party.ID) error {
	msg := &Message{
		From:    h.selfID,
		To:      to,
		Content: content,
	}
	select {
	case out <- msg:
		return nil
	default:
		return errors.New("messages out channel is full")
	}
}

// ProtocolID is a string identifier for this protocol.
func (h *Helper) ProtocolID() string { return h.protocolID }

// FinalRoundNumber is the number of rounds before the output round.
func (h *Helper) FinalRoundNumber() Number { return h.finalRoundNumber }

// SSID the unique identifier for this protocol execution.
func (h *Helper) SSID() []byte { return h.ssid }

// SelfID is this party's ID.
func (h *Helper) SelfID() party.ID { return h.selfID }

// PartyIDs is a sorted slice of participating parties in this protocol.
func (h *Helper) PartyIDs() party.IDSlice { return h.partyIDs }

// N returns the number of participants.
func (h *Helper) N() int { return len(h.partyIDs) }

// OtherPartyIDs returns a sorted list of parties that does not contain SelfID.
func (h *Helper) OtherPartyIDs() party.IDSlice { return h.partyIDs.Remove(h.selfID) }

// Group returns the curve used for this protocol.
func (h *Helper) Group() curve.Curve { return h.group }
