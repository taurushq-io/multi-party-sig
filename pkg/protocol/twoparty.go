package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/internal/round"
)

// TwoPartyHandler represents a restriction of the Handler for 2 party protocols.
type TwoPartyHandler struct {
	round    round.Session
	leader   bool
	err      error
	result   interface{}
	messages map[round.Number]*Message
	out      chan *Message
	mtx      sync.Mutex
}

func NewTwoPartyHandler(create StartFunc, sessionID []byte, leader bool) (*TwoPartyHandler, error) {
	r, err := create(sessionID)
	if err != nil {
		return nil, fmt.Errorf("protocol: failed to create round: %w", err)
	}
	handler := &TwoPartyHandler{
		round:    r,
		leader:   leader,
		err:      nil,
		result:   nil,
		messages: map[round.Number]*Message{},
		out:      make(chan *Message, 2),
		mtx:      sync.Mutex{},
	}
	if leader {
		handler.advance()
	}
	return handler, nil
}

func (h *TwoPartyHandler) Result() (interface{}, error) {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	if h.result != nil {
		return h.result, nil
	}
	if h.err != nil {
		return nil, h.err
	}
	return nil, errors.New("protocol: not finished")
}

func (h *TwoPartyHandler) Listen() <-chan *Message {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	return h.out
}

func (h *TwoPartyHandler) Stop() {
	if h.err != nil || h.result != nil {
		h.abort(errors.New("aborted by user"))
	}
}

func (h *TwoPartyHandler) String() string {
	return fmt.Sprintf("party: %s, protocol: %s", h.round.SelfID(), h.round.ProtocolID())
}

func (h *TwoPartyHandler) abort(err error) {
	if err != nil {
		h.err = err
		select {
		case h.out <- &Message{
			SSID:     h.round.SSID(),
			From:     h.round.SelfID(),
			Protocol: h.round.ProtocolID(),
			Data:     []byte(h.err.Error()),
		}:
		default:
		}
	}
	close(h.out)
}

func (h *TwoPartyHandler) canAdvance() bool {
	if h.round.MessageContent() == nil {
		return true
	}
	if h.messages[h.round.Number()] != nil {
		return true
	}
	return false
}

func extractRoundMessage(r round.Session, msg *Message) (round.Message, error) {
	content := r.MessageContent()
	if err := cbor.Unmarshal(msg.Data, content); err != nil {
		return round.Message{}, fmt.Errorf("failed to unmarshal message: %w", err)
	}
	roundMsg := round.Message{
		From:      msg.From,
		To:        msg.To,
		Content:   content,
		Broadcast: msg.Broadcast,
	}
	return roundMsg, nil
}

func (h *TwoPartyHandler) verifyMessage(msg *Message) error {
	if msg == nil {
		return nil
	}
	r := h.round
	roundMsg, err := extractRoundMessage(r, msg)
	if err != nil {
		return err
	}

	if err = r.VerifyMessage(roundMsg); err != nil {
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}

	if err = r.StoreMessage(roundMsg); err != nil {
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}

	return nil
}

func (h *TwoPartyHandler) advance() {
	for h.canAdvance() {
		msg := h.messages[h.round.Number()]
		if err := h.verifyMessage(msg); err != nil {
			h.abort(err)
			return
		}
		out := make(chan *round.Message, 1)
		newRound, err := h.round.Finalize(out)
		if err != nil || newRound == nil {
			h.abort(err)
			return
		}
		close(out)
		for roundMsg := range out {
			data, err := cbor.Marshal(roundMsg.Content)
			if err != nil {
				panic(fmt.Errorf("failed to marshal round message: %w", err))
			}
			msg := &Message{
				SSID:                  newRound.SSID(),
				From:                  newRound.SelfID(),
				To:                    roundMsg.To,
				Protocol:              newRound.ProtocolID(),
				RoundNumber:           roundMsg.Content.RoundNumber(),
				Data:                  data,
				Broadcast:             roundMsg.Broadcast,
				BroadcastVerification: nil,
			}
			h.out <- msg
		}
		h.round = newRound
		switch R := newRound.(type) {
		// An abort happened
		case *round.Abort:
			h.abort(R.Err)
			return
		// We have the result
		case *round.Output:
			h.result = R.Result
			h.abort(nil)
			return
		default:
		}
	}
}

func (h *TwoPartyHandler) CanAccept(msg *Message) bool {
	r := h.round
	if msg == nil {
		return false
	}
	if !msg.IsFor(r.SelfID()) {
		return false
	}
	if msg.Protocol != r.ProtocolID() {
		return false
	}
	if !bytes.Equal(msg.SSID, r.SSID()) {
		return false
	}
	if !r.PartyIDs().Contains(msg.From) {
		return false
	}
	if msg.Data == nil {
		return false
	}
	if msg.RoundNumber > r.FinalRoundNumber() {
		return false
	}
	return true
}

func (h *TwoPartyHandler) Accept(msg *Message) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	if !h.CanAccept(msg) || h.err != nil || h.result != nil {
		return
	}

	if msg.RoundNumber == 0 {
		h.abort(fmt.Errorf("aborted by other party with error: \"%s\"", msg.Data))
		return
	}

	h.messages[msg.RoundNumber] = msg

	h.advance()
}
