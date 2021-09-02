package round

import (
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

// Helper implements Session without Round, and can therefore be embedded in the first round of a protocol
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

// NewSession creates a new *Helper which can be embedded in the first Round,
// so that the full struct implements Session.
// `sessionID` is an optional byte slice that can be provided by the user.
// When used, it should be unique for each execution of the protocol.
// It could be a simple counter which is incremented after execution,  or a common random string.
// `auxInfo` is a variable list of objects which should be included in the session's hash state.
func NewSession(info Info, sessionID []byte, pl *pool.Pool, auxInfo ...hash.WriterToWithDomain) (*Helper, error) {
	partyIDs := party.NewIDSlice(info.PartyIDs)
	if !partyIDs.Valid() {
		return nil, errors.New("session: partyIDs invalid")
	}

	// verify our ID is present
	if !partyIDs.Contains(info.SelfID) {
		return nil, errors.New("session: selfID not included in partyIDs")
	}

	// make sure the threshold is correct
	if info.Threshold < 0 || info.Threshold > math.MaxUint32 {
		return nil, fmt.Errorf("session: threshold %d is invalid", info.Threshold)
	}

	// the number of users satisfies the threshold
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

// BroadcastMessage constructs a Message from the broadcast Content, and sets the header correctly.
// An error is returned if the message cannot be sent to the out channel.
func (h *Helper) BroadcastMessage(out chan<- *Message, broadcastContent Content) error {
	msg := &Message{
		From:      h.info.SelfID,
		Broadcast: true,
		Content:   broadcastContent,
	}
	select {
	case out <- msg:
		return nil
	default:
		return ErrOutChanFull
	}
}

// SendMessage is a convenience method for safely sending content to some party. If the message is
// intended for all participants (but does not require reliable broadcast), the `to` field may be empty ("").
// Returns an error if the message failed to send over out channel.
// `out` is expected to be a buffered channel with enough capacity to store all messages.
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
		return ErrOutChanFull
	}
}

// Hash returns copy of the hash function of this protocol execution.
func (h *Helper) Hash() *hash.Hash {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	return h.hash.Clone()
}

// ResultRound returns a round that contains only the result of the protocol.
// This indicates to the used that the protocol is finished.
func (h *Helper) ResultRound(result interface{}) Session {
	return &Output{
		Helper: h,
		Result: result,
	}
}

// AbortRound returns a round that contains only the culprits that were able to be identified during
// a faulty execution of the protocol. The error returned by Round.Finalize() in this case should still be nil.
func (h *Helper) AbortRound(err error, culprits ...party.ID) Session {
	return &Abort{
		Helper:   h,
		Culprits: culprits,
		Err:      err,
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
