package round

import (
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

// Helper implements Session without the round, and can therefore be embedded in the first round of a protocol
// in order to satisfy the Session interface.
type Helper struct {
	info Info

	// Pool allows us to parallelize certain operations
	Pool *pool.Pool

	// partyIDs is a sorted slice of Info.PartyIDs.
	partyIDs party.IDSlice
	// otherPartyIDs is the same as partyIDs without selfID
	otherPartyIDs party.IDSlice

	// ssid the unique identifier for this protocol execution
	ssid []byte

	hash *hash.Hash

	mtx sync.Mutex
}

// SessionID is an optional byte slice that can be provided by the user.
// When used, it should be unique for each execution of the protocol.
// It could be a simple counter which is incremented after execution,
// or a common random string.
func NewSession(info Info, sessionID []byte, pl *pool.Pool, auxInfo ...hash.WriterToWithDomain) (*Helper, error) {
	partyIDs := party.NewIDSlice(info.PartyIDs)
	if !partyIDs.Valid() {
		return nil, errors.New("session: partyIDs invalid")
	}

	// verify our ID is present
	if !partyIDs.Contains(info.SelfID) {
		return nil, errors.New("session: selfID not included in partyIDs")
	}

	if info.Threshold < 0 || info.Threshold > math.MaxUint32 {
		return nil, fmt.Errorf("session: threshold %d is invalid", info.Threshold)
	}

	if n := len(partyIDs); n <= 0 || info.Threshold > n-1 {
		return nil, fmt.Errorf("session: threshold %d is invalid for number of parties %d", info.Threshold, n)
	}

	var err error
	h := hash.New()

	if sessionID != nil {
		if err = h.WriteAny(&hash.BytesWithDomain{
			TheDomain: "Session ID",
			Bytes:     sessionID,
		}); err != nil {
			return nil, fmt.Errorf("session: %w", err)
		}
	}

	if err = h.WriteAny(&hash.BytesWithDomain{
		TheDomain: "Protocol ID",
		Bytes:     []byte(info.ProtocolID),
	}); err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}

	if info.Group != nil {
		if err = h.WriteAny(&hash.BytesWithDomain{
			TheDomain: "Group Name",
			Bytes:     []byte(info.Group.Name()),
		}); err != nil {
			return nil, fmt.Errorf("session: %w", err)
		}
	}

	if err = h.WriteAny(partyIDs); err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}

	if err = h.WriteAny(types.ThresholdWrapper(info.Threshold)); err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}

	for _, a := range auxInfo {
		if a == nil {
			continue
		}
		if err = h.WriteAny(a); err != nil {
			return nil, fmt.Errorf("session: %w", err)
		}
	}

	return &Helper{
		info:          info,
		Pool:          pl,
		partyIDs:      partyIDs,
		otherPartyIDs: partyIDs.Remove(info.SelfID),
		ssid:          h.Clone().Sum(),
		hash:          h,
	}, nil
}

// getHash returns a new hash.Hash function initialized with the full SSID.
// It assumes that the state is in a correct, and can panic if it is not.
// Calling hash.Sum() on the resulting hash function returns the hash of the SSID.
// It computes Hash(sid, 𝔾, n, P₁, …, Pₙ, t, auxInfo).

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
// It panics if the content is not able to be marshalled.
// SendMessage is a convenience function for all rounds that attempts to send the message to the channel.
// If the channel is full or closed, an error is returned.
func (h *Helper) SendMessage(out chan<- *Message, content Content, to party.ID) error {
	msg := &Message{
		From:    h.info.SelfID,
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

// Hash returns copy of the hash function of this protocol execution.
func (h *Helper) Hash() *hash.Hash {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	return h.hash.Clone()
}

func (h *Helper) ResultRound(result interface{}) Session {
	return &Output{
		Helper: h,
		Result: result,
	}
}

// ProtocolID is an identifier for this protocol.
func (h *Helper) ProtocolID() string { return h.info.ProtocolID }

// FinalRoundNumber is the number of rounds before the output round.
func (h *Helper) FinalRoundNumber() Number { return h.info.FinalRoundNumber }

// SSID the unique identifier for this protocol execution.
func (h *Helper) SSID() []byte { return h.ssid }

// SelfID is this party's ID.
func (h *Helper) SelfID() party.ID { return h.info.SelfID }

// PartyIDs is a sorted slice of participating parties in this protocol.
func (h *Helper) PartyIDs() party.IDSlice { return h.partyIDs }

// OtherPartyIDs returns a sorted list of parties that does not contain SelfID.
func (h *Helper) OtherPartyIDs() party.IDSlice { return h.otherPartyIDs }

// Threshold is the maximum number of parties that are assumed to be corrupted during the execution of this protocol.
func (h *Helper) Threshold() int { return h.info.Threshold }

// N returns the number of participants.
func (h *Helper) N() int { return len(h.info.PartyIDs) }

// Group returns the curve used for this protocol.
func (h *Helper) Group() curve.Curve { return h.info.Group }
