package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/rs/zerolog"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

// StartFunc is function that creates the first round of a protocol. It returns
type StartFunc func() (round.Round, Info, error)

type Handler struct {
	queue *queue
	info  Info
	mtx   sync.Mutex

	Log zerolog.Logger

	done bool

	outChan  chan *message.Message
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
		queue:    &queue{},
		info:     info,
		outChan:  make(chan *message.Message, 2*info.N()),
		r:        r,
		received: received,
	}
	h.Log = zerolog.New(zerolog.NewConsoleWriter()).Level(zerolog.InfoLevel).With().
		Str("protocol", string(info.ProtocolID())).
		Str("party", string(info.SelfID())).
		Int("round", int(h.roundNumber())).
		Stack().
		Logger()
	h.Log.Info().Msg("start")

	if err = h.finishRound(); err != nil {
		return nil, err
	}
	return h, nil
}

// Listen returns a channel with outgoing messages that must be sent to other parties.
// If Message.To is nil, then it should be reliably broadcast to all parties.
// The channel is closed
func (h *Handler) Listen() <-chan *message.Message {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	return h.outChan
}

func (h *Handler) Result() (interface{}, error) {
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

func (h *Handler) Update(msg *message.Message) error {
	h.mtx.Lock()
	defer func() {
		if h.err != nil {
			h.stop()
		}
		h.mtx.Unlock()
	}()

	h.Log.Debug().Stringer("msg", msg).Msg("got new message")

	if h.err != nil {
		return h.err
	}

	if h.receivedAll() {
		if err := h.finishRound(); err != nil {
			h.Log.Error().Err(err).Msg("finish round")
			return err
		}
	}

	if msg != nil {
		if err := h.validate(msg); err != nil {
			h.Log.Error().Err(err).Stringer("msg", msg).Msg("failed to validate")
			return err
		}
		if err := h.handleMessage(msg); err != nil {
			h.Log.Error().Err(err).Stringer("msg", msg).Msg("failed to handle")
			return err
		}
	}

	if h.receivedAll() {
		if err := h.finishRound(); err != nil {
			h.Log.Error().Err(err).Stringer("msg", msg).Msg("failed to finish")
			return err
		}
	}

	return nil
}

func (h *Handler) validate(msg *message.Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}

	if !msg.IsFor(h.info.SelfID()) {
		return message.ErrMessageWrongDestination
	}

	// check SSID
	if !bytes.Equal(h.info.SSID(), msg.SSID) {
		return message.ErrMessageWrongSSID
	}

	// check protocol ID
	if msg.Protocol != h.info.ProtocolID() {
		return message.ErrMessageWrongProtocolID
	}

	// check if message for unexpected round
	if msg.RoundNumber > h.info.FinalRoundNumber() {
		return message.ErrMessageInvalidRoundNumber
	}

	// do we know the sender
	if _, ok := h.received[msg.From]; !ok {
		return message.ErrMessageUnknownSender
	}

	destination := party.IDSlice(msg.To)

	// if not broadcast, make sure we are the intended recipient
	if len(destination) != 0 && !destination.Contains(h.info.SelfID()) {
		return message.ErrMessageWrongDestination
	}

	// previous round
	currentRound := h.roundNumber()
	if msg.RoundNumber < currentRound {
		return message.ErrMessageDuplicate
	}

	return nil
}

func (h *Handler) handleMessage(msg *message.Message) error {
	if msg.RoundNumber != h.roundNumber() {
		h.Log.Info().Stringer("msg", msg).Msg("storing message")
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

func (h *Handler) finishRound() error {
	defer func() {
		if h.err != nil || h.result != nil {
			if h.err != nil {
				h.Log.Error().Err(h.err).Msg("finished with err")
			}
		}
	}()
	// get new messages
	if err := h.r.GenerateMessages(h.outChan); err != nil {
		h.err = h.wrapError(err, "")
		h.Log.Error().Err(h.err).Msg("generate messages")
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
		h.done = true
		return h.err
	}

	h.r = nextRound
	h.Log.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Int("round", int(h.roundNumber()))
	})
	h.Log.Info().Msg("round advanced")

	// reset received state
	newReceived := make(map[party.ID]bool, len(h.received))
	for id := range h.received {
		newReceived[id] = false
	}
	h.received = newReceived

	queued := h.queue.Get(h.roundNumber())
	if len(queued) > 0 {
		h.Log.Info().Int("count", len(queued)).Msg("retrieving from queue")
	}
	for _, msg := range queued {
		if err := h.handleMessage(msg); err != nil {
			return err
		}
	}

	if h.receivedAll() {
		h.Log.Info().Msg("recursion")
		return h.finishRound()
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

// wrapError wraps a Round error with information about the current round and a possible culprit
func (h *Handler) wrapError(err error, culprit party.ID) error {
	return &Error{
		RoundNumber: h.roundNumber(),
		Culprit:     culprit,
		Err:         err,
	}
}

func (h *Handler) roundNumber() types.RoundNumber {
	return h.r.MessageContent().RoundNumber()
}

func (h *Handler) stop() {
	if !h.done {
		h.done = true
		close(h.outChan)
	}
}
