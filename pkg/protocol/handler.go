package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

// StartFunc is function that creates the first round of a protocol for a given session.Session.
type StartFunc func() (round.Round, Info, error)

type Handler struct {
	queue Queue
	info  Info
	mtx   sync.Mutex

	doneChan chan struct{}
	outChan  chan *round.Message
	r        round.Round
	result   interface{}
	err      error
	received map[party.ID]bool
}

func NewHandler(create StartFunc) (*Handler, error) {
	r, info, err := create()
	if err != nil {
		return nil, fmt.Errorf("protocol: failed to create round: %w", err)
	}
	received := make(map[party.ID]bool, info.N())
	for _, id := range info.OtherPartyIDs() {
		received[id] = false
	}
	h := &Handler{
		queue:    newQueue(info.N() * int(info.FinalRoundNumber())),
		info:     info,
		doneChan: make(chan struct{}),
		outChan:  make(chan *round.Message, info.N()),

		r:        r,
		received: received,
	}

	if err = h.finishRound(); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Handler) validate(msg *round.Message) error {
	if msg.Content == nil {
		return ErrMessageNilContent
	}

	// check SSID
	if !bytes.Equal(h.info.SSID(), msg.SSID) {
		return ErrMessageWrongSSID
	}

	// check protocol ID
	if msg.Protocol != h.info.ProtocolID() {
		return ErrMessageWrongProtocolID
	}

	// check if message for previous round or beyond expected
	if msg.RoundNumber <= round.First || msg.RoundNumber > h.info.FinalRoundNumber() {
		return ErrMessageInvalidRoundNumber
	}

	// message cannot be from ourselves
	if msg.From == h.info.SelfID() {
		return ErrMessageFromSelf
	}

	// do we know the sender
	if _, ok := h.received[msg.From]; !ok {
		return ErrMessageUnknownSender
	}

	destination := party.IDSlice(msg.To)
	// .To must be sorted
	if !destination.Sorted() {
		return ErrMessageNotSorted
	}

	// if not broadcast, make sure we are the intended recipient
	if len(destination) != 0 && !destination.Contains(h.info.SelfID()) {
		return ErrMessageWrongDestination
	}

	// previous round
	currentRound := h.roundNumber()
	if msg.RoundNumber < currentRound {
		return ErrMessageDuplicate
	}

	return nil
}

func (h *Handler) handleMessage(msg *round.Message) error {
	if msg.RoundNumber != h.roundNumber() {
		fmt.Println("storing ", msg)
		return h.queue.Store(msg)
	}
	if h.received[msg.From] {
		return ErrMessageDuplicate
	}

	h.received[msg.From] = true

	// unmarshal message
	content := h.r.MessageContent()
	if err := msg.UnmarshalContent(content); err != nil {
		h.err = h.wrapError(err, msg.From)
		return h.err
	}

	// process
	if err := h.r.ProcessMessage(msg.From, content); err != nil {
		h.err = h.wrapError(err, msg.From)
		return h.err
	}
	return nil
}

func (h *Handler) receivedAll() bool {
	for _, received := range h.received {
		if !received {
			return false
		}
	}
	return true
}

func (h *Handler) finishRound() error {
	defer func() {
		if h.err != nil || h.result != nil {
			fmt.Println("stopping finish")
			h.stop()
			select {
			case <-h.doneChan:
				fmt.Println("closed real")
			default:
				fmt.Println("not closed")
			}
		}
	}()
	// get new messages
	if err := h.r.GenerateMessages(h.outChan); err != nil {
		h.err = h.wrapError(err, "")
		return h.err
	}

	// get new round
	nextRound := h.r.Next()

	// a nil round indicates we have reached the final round
	if nextRound == nil {
		h.result = h.r.(round.Final).Result()
		h.r = nil
		if h.result == nil {
			h.err = ErrProtocolFinalRoundNotReached
		}
		h.stop()
		return h.err
	}

	h.r = nextRound
	fmt.Println(h.info.SelfID(), "next", h.roundNumber())

	// reset received state
	newReceived := make(map[party.ID]bool, len(h.received))
	for id := range h.received {
		newReceived[id] = false
	}
	h.received = newReceived

	for _, msg := range h.queue.Get(h.roundNumber()) {
		if err := h.handleMessage(msg); err != nil {
			return err
		}
	}

	if h.receivedAll() {
		fmt.Println("rec")
		return h.finishRound()
	}

	return nil
}

func (h *Handler) Update(msg *round.Message) error {
	fmt.Println(h.info.SelfID(), h.roundNumber(), "Update", msg)
	h.mtx.Lock()
	defer h.mtx.Unlock()

	if h.done() {
		if h.err != nil {
			return h.err
		}
		return nil
	}

	if h.receivedAll() {
		return h.finishRound()
	}

	if msg != nil {
		if err := h.validate(msg); err != nil {
			return err
		}
		if err := h.handleMessage(msg); err != nil {
			return err
		}
	}

	if h.receivedAll() {
		return h.finishRound()
	}

	return nil
}

// wrapError wraps a Round error with information about the current round and a possible culprit
func (h *Handler) wrapError(err error, culprit party.ID) error {
	if err != nil {
		return &Error{
			RoundNumber: h.roundNumber(),
			Culprit:     culprit,
			Err:         err,
		}
	}
	return nil
}

func (h *Handler) roundNumber() types.RoundNumber {
	return h.r.MessageContent().RoundNumber()
}

// Listen returns a channel with outgoing messages that must be sent to other parties.
// If Message.To is nil, then it should be reliably broadcast to all parties.
func (h *Handler) Listen() <-chan *round.Message {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	if h.done() {
		c := make(chan *round.Message)
		close(c)
		return c
	}
	return h.outChan
}

func (h *Handler) stop() {
	select {
	case <-h.doneChan:
	default:
		close(h.outChan)
		close(h.doneChan)
		fmt.Println("close")
	}
}

func (h *Handler) Stop() {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	h.stop()
}

// Done can be used within a select statement to know when the protocol reaches an error or
// is finished.
func (h *Handler) Done() <-chan struct{} {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	return h.doneChan
}

func (h *Handler) done() bool {
	select {
	case <-h.doneChan:
		return true
	default:
		return false
	}
}

func (h *Handler) Result() (interface{}, error) {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	if !h.done() {
		return nil, errors.New("protocol: not finished")
	}
	if h.err != nil {
		return nil, h.err
	}
	return h.result, nil
}
