package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// StartFunc is function that creates the first round of a protocol.
// It returns the first round initialized with the session information.
// If the creation fails (likely due to misconfiguration), and error is returned.
//
// An optional sessionID can be provided, which should unique among all protocol executions.
type StartFunc func(sessionID []byte) (round.Session, error)

// Handler represents some kind of handler for a protocol.
type Handler interface {
	// Result should return the result of running the protocol, or an error
	Result() (interface{}, error)
	// Listen returns a channel which will receive new messages
	Listen() <-chan *Message
	// Stop should abort the protocol execution.
	Stop()
	// CanAccept checks whether or not a message can be accepted at the current point in the protocol.
	CanAccept(msg *Message) bool
	// Accept advances the protocol execution after receiving a message.
	Accept(msg *Message)
}

// MultiHandler represents an execution of a given protocol.
// It provides a simple interface for the user to receive/deliver protocol messages.
type MultiHandler struct {
	currentRound    round.Session
	rounds          map[round.Number]round.Session
	err             *Error
	result          interface{}
	messages        map[round.Number]map[party.ID]*Message
	broadcast       map[round.Number]map[party.ID]*Message
	broadcastHashes map[round.Number][]byte
	out             chan *Message
	mtx             sync.Mutex
}

// NewMultiHandler expects a StartFunc for the desired protocol. It returns a handler that the user can interact with.
func NewMultiHandler(create StartFunc, sessionID []byte) (*MultiHandler, error) {
	r, err := create(sessionID)
	if err != nil {
		return nil, fmt.Errorf("protocol: failed to create round: %w", err)
	}
	h := &MultiHandler{
		currentRound:    r,
		rounds:          map[round.Number]round.Session{r.Number(): r},
		messages:        newQueue(r.OtherPartyIDs(), r.FinalRoundNumber()),
		broadcast:       newQueue(r.OtherPartyIDs(), r.FinalRoundNumber()),
		broadcastHashes: map[round.Number][]byte{},
		out:             make(chan *Message, 2*r.N()),
	}
	h.finalize()
	return h, nil
}

// Result returns the protocol result if the protocol completed successfully. Otherwise an error is returned.
func (h *MultiHandler) Result() (interface{}, error) {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	if h.result != nil {
		return h.result, nil
	}
	if h.err != nil {
		return nil, *h.err
	}
	return nil, errors.New("protocol: not finished")
}

// Listen returns a channel with outgoing messages that must be sent to other parties.
// The message received should be _reliably_ broadcast if msg.Broadcast is true.
// The channel is closed when either an error occurs or the protocol detects an error.
func (h *MultiHandler) Listen() <-chan *Message {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	return h.out
}

// CanAccept returns true if the message is designated for this protocol protocol execution.
func (h *MultiHandler) CanAccept(msg *Message) bool {
	r := h.currentRound
	if msg == nil {
		return false
	}
	// are we the intended recipient
	if !msg.IsFor(r.SelfID()) {
		return false
	}
	// is the protocol ID correct
	if msg.Protocol != r.ProtocolID() {
		return false
	}
	// check for same SSID
	if !bytes.Equal(msg.SSID, r.SSID()) {
		return false
	}
	// do we know the sender
	if !r.PartyIDs().Contains(msg.From) {
		return false
	}

	// data is cannot be nil
	if msg.Data == nil {
		return false
	}

	// check if message for unexpected round
	if msg.RoundNumber > r.FinalRoundNumber() {
		return false
	}

	if msg.RoundNumber < r.Number() && msg.RoundNumber > 0 {
		return false
	}

	return true
}

// Accept tries to process the given message. If an abort occurs, the channel returned by Listen() is closed,
// and an error is returned by Result().
//
// This function may be called concurrently from different threads but may block until all previous calls have finished.
func (h *MultiHandler) Accept(msg *Message) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	// exit early if the message is bad, or if we are already done
	if !h.CanAccept(msg) || h.err != nil || h.result != nil || h.duplicate(msg) {
		return
	}

	// a msg with roundNumber 0 is considered an abort from another party
	if msg.RoundNumber == 0 {
		h.abort(fmt.Errorf("aborted by other party with error: \"%s\"", msg.Data), msg.From)
		return
	}

	h.store(msg)
	if h.currentRound.Number() != msg.RoundNumber {
		return
	}

	if msg.Broadcast {
		if err := h.verifyBroadcastMessage(msg); err != nil {
			h.abort(err, msg.From)
			return
		}
	} else {
		if err := h.verifyMessage(msg); err != nil {
			h.abort(err, msg.From)
			return
		}
	}

	h.finalize()
}

func (h *MultiHandler) verifyBroadcastMessage(msg *Message) error {
	r, ok := h.rounds[msg.RoundNumber]
	if !ok {
		return nil
	}

	// try to convert the raw message into a round.Message
	roundMsg, err := getRoundMessage(msg, r)
	if err != nil {
		return err
	}

	// store the broadcast message for this round
	if err = r.(round.BroadcastRound).StoreBroadcastMessage(roundMsg); err != nil {
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}

	// if the round only expected a broadcast message, we can safely return
	if !expectsNormalMessage(r) {
		return nil
	}

	// otherwise, we can try to handle the p2p message that may be stored.
	msg = h.messages[msg.RoundNumber][msg.From]
	if msg == nil {
		return nil
	}

	return h.verifyMessage(msg)
}

// verifyMessage tries to handle a normal (non reliably broadcast) message for this current round.
func (h *MultiHandler) verifyMessage(msg *Message) error {
	// we simply return if we haven't reached the right round.
	r, ok := h.rounds[msg.RoundNumber]
	if !ok {
		return nil
	}

	// exit if we don't yet have the broadcast message
	if _, ok = r.(round.BroadcastRound); ok {
		q := h.broadcast[msg.RoundNumber]
		if q == nil || q[msg.From] == nil {
			return nil
		}
	}

	roundMsg, err := getRoundMessage(msg, r)
	if err != nil {
		return err
	}

	// verify message for round
	if err = r.VerifyMessage(roundMsg); err != nil {
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}

	if err = r.StoreMessage(roundMsg); err != nil {
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}

	return nil
}

func (h *MultiHandler) finalize() {
	// only finalize if we have received all messages
	if !h.receivedAll() {
		return
	}
	if !h.checkBroadcastHash() {
		h.abort(errors.New("broadcast verification failed"))
		return
	}

	out := make(chan *round.Message, h.currentRound.N()+1)
	// since we pass a large enough channel, we should never get an error
	r, err := h.currentRound.Finalize(out)
	close(out)
	// either we got an error due to some problem on our end (sampling etc)
	// or the new round is nil (should not happen)
	if err != nil || r == nil {
		h.abort(err, h.currentRound.SelfID())
		return
	}

	// forward messages with the correct header.
	for roundMsg := range out {
		data, err := cbor.Marshal(roundMsg.Content)
		if err != nil {
			panic(fmt.Errorf("failed to marshal round message: %w", err))
		}
		msg := &Message{
			SSID:                  r.SSID(),
			From:                  r.SelfID(),
			To:                    roundMsg.To,
			Protocol:              r.ProtocolID(),
			RoundNumber:           roundMsg.Content.RoundNumber(),
			Data:                  data,
			Broadcast:             roundMsg.Broadcast,
			BroadcastVerification: h.broadcastHashes[r.Number()-1],
		}
		if msg.Broadcast {
			h.store(msg)
		}
		h.out <- msg
	}

	roundNumber := r.Number()
	// if we get a round with the same number, we can safely assume that we got the same one.
	if _, ok := h.rounds[roundNumber]; ok {
		return
	}
	h.rounds[roundNumber] = r
	h.currentRound = r

	// either we get the current round, the next one, or one of the two final ones
	switch R := r.(type) {
	// An abort happened
	case *round.Abort:
		h.abort(R.Err, R.Culprits...)
		return
	// We have the result
	case *round.Output:
		h.result = R.Result
		h.abort(nil)
		return
	default:
	}

	if _, ok := r.(round.BroadcastRound); ok {
		// handle queued broadcast messages, which will then check the subsequent normal message
		for id, m := range h.broadcast[roundNumber] {
			if m == nil || id == r.SelfID() {
				continue
			}
			// if false, we aborted and so we return
			if err = h.verifyBroadcastMessage(m); err != nil {
				h.abort(err, m.From)
				return
			}
		}
	} else {
		// handle simple queued messages
		for _, m := range h.messages[roundNumber] {
			if m == nil {
				continue
			}
			// if false, we aborted and so we return
			if err = h.verifyMessage(m); err != nil {
				h.abort(err, m.From)
				return
			}
		}
	}

	// we only do this if the current round has changed
	h.finalize()
}

func (h *MultiHandler) abort(err error, culprits ...party.ID) {
	if err != nil {
		h.err = &Error{
			Culprits: culprits,
			Err:      err,
		}
		select {
		case h.out <- &Message{
			SSID:     h.currentRound.SSID(),
			From:     h.currentRound.SelfID(),
			Protocol: h.currentRound.ProtocolID(),
			Data:     []byte(h.err.Error()),
		}:
		default:
		}

	}
	close(h.out)
}

// Stop cancels the current execution of the protocol, and alerts the other users.
func (h *MultiHandler) Stop() {
	if h.err != nil || h.result != nil {
		h.abort(errors.New("aborted by user"), h.currentRound.SelfID())
	}
}

func expectsNormalMessage(r round.Session) bool {
	return r.MessageContent() != nil
}

func (h *MultiHandler) receivedAll() bool {
	r := h.currentRound
	number := r.Number()
	// check all broadcast messages
	if _, ok := r.(round.BroadcastRound); ok {
		if h.broadcast[number] == nil {
			return true
		}
		for _, id := range r.PartyIDs() {
			msg := h.broadcast[number][id]
			if msg == nil {
				return false
			}
		}

		// create hash of all message for this round
		if h.broadcastHashes[number] == nil {
			hashState := r.Hash()
			for _, id := range r.PartyIDs() {
				msg := h.broadcast[number][id]
				_ = hashState.WriteAny(&hash.BytesWithDomain{
					TheDomain: "Message",
					Bytes:     msg.Hash(),
				})
			}
			h.broadcastHashes[number] = hashState.Sum()
		}
	}

	// check all normal messages
	if expectsNormalMessage(r) {
		if h.messages[number] == nil {
			return true
		}
		for _, id := range r.OtherPartyIDs() {
			if h.messages[number][id] == nil {
				return false
			}
		}
	}
	return true
}

func (h *MultiHandler) duplicate(msg *Message) bool {
	if msg.RoundNumber == 0 {
		return false
	}
	var q map[party.ID]*Message
	if msg.Broadcast {
		q = h.broadcast[msg.RoundNumber]
	} else {
		q = h.messages[msg.RoundNumber]
	}
	// technically, we already received the nil message since it is not expected :)
	if q == nil {
		return true
	}
	return q[msg.From] != nil
}

func (h *MultiHandler) store(msg *Message) {
	var q map[party.ID]*Message
	if msg.Broadcast {
		q = h.broadcast[msg.RoundNumber]
	} else {
		q = h.messages[msg.RoundNumber]
	}
	if q == nil || q[msg.From] != nil {
		return
	}
	q[msg.From] = msg
}

// getRoundMessage attempts to unmarshal a raw Message for round `r` in a round.Message.
// If an error is returned, we should abort.
func getRoundMessage(msg *Message, r round.Session) (round.Message, error) {
	var content round.Content

	// there are two possible content messages
	if msg.Broadcast {
		b, ok := r.(round.BroadcastRound)
		if !ok {
			return round.Message{}, errors.New("got broadcast message when none was expected")
		}
		content = b.BroadcastContent()
	} else {
		content = r.MessageContent()
	}

	// unmarshal message
	if err := cbor.Unmarshal(msg.Data, content); err != nil {
		return round.Message{}, fmt.Errorf("failed to unmarshal: %w", err)
	}
	roundMsg := round.Message{
		From:      msg.From,
		To:        msg.To,
		Content:   content,
		Broadcast: msg.Broadcast,
	}
	return roundMsg, nil
}

// checkBroadcastHash is run after receivedAll() and checks whether all provided verification hashes are correct.
func (h *MultiHandler) checkBroadcastHash() bool {
	number := h.currentRound.Number()
	// check BroadcastVerification
	previousHash := h.broadcastHashes[number-1]
	if previousHash == nil {
		return true
	}

	for _, msg := range h.messages[number] {
		if msg != nil && !bytes.Equal(previousHash, msg.BroadcastVerification) {
			return false
		}
	}
	for _, msg := range h.broadcast[number] {
		if msg != nil && !bytes.Equal(previousHash, msg.BroadcastVerification) {
			return false
		}
	}
	return true
}

func newQueue(senders []party.ID, rounds round.Number) map[round.Number]map[party.ID]*Message {
	n := len(senders)
	q := make(map[round.Number]map[party.ID]*Message, rounds)
	for i := round.Number(2); i <= rounds; i++ {
		q[i] = make(map[party.ID]*Message, n)
		for _, id := range senders {
			q[i][id] = nil
		}
	}
	return q
}

func (h *MultiHandler) String() string {
	return fmt.Sprintf("party: %s, protocol: %s", h.currentRound.SelfID(), h.currentRound.ProtocolID())
}
