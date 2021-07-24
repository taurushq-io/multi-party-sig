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

// StartFunc is function that creates the first round of a protocol.
// It returns the first round, as well as Info containing static information about the protocol.
// If the creation fails (likely due to misconfiguration), and error is returned.
type StartFunc func() (round.Round, Info, error)

// Handler represents an execution of a given protocol.
// It provides a simple interface for the user to receive/deliver protocol messages.
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

// NewHandler expects a StartFunc for the desired protocol. It returns a handler that the user can interact with.
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
// The message received should be _reliably_ broadcast if msg.Broadcast() is true.
// The channel is closed when either an error occurs or the protocol detects an error.
func (h *Handler) Listen() <-chan *message.Message {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	return h.outChan
}

// Result returns the protocol result if the protocol completed successfully. Otherwise an error is returned.
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

// Update performs the following:
// - Check header information about msg and make sure we can accept it in this protocol execution
// - If the message is for a later round, store it in a queue for later
// - Validate the contents of the message for this round
// - If all messages for this round have been received, proceed to the next round
// - Retrieve from the queue any message intended for this round.
//
// This function may be called concurrently from different threads but may block until all previous calls have finished.
func (h *Handler) Update(msg *message.Message) error {
	// return early if we are already finished
	if h.result != nil || h.err != nil {
		return h.err
	}
	h.mtx.Lock()
	defer func() {
		if h.err != nil {
			h.stop()
		}
		h.mtx.Unlock()
	}()

	if msg != nil {
		h.Log.Debug().Stringer("msg", msg).Msg("got new message")
		if err := h.validate(msg); err != nil {
			h.Log.Warn().Err(err).Stringer("msg", msg).Msg("failed to validate")
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
		h.Log.Debug().Str("from", string(msg.From)).Int("roundNumber", int(msg.RoundNumber)).Msg("storing message")
		return h.queue.Store(msg)
	}
	if h.received[msg.From] {
		return message.ErrMessageDuplicate
	}

	h.received[msg.From] = true

	// unmarshal message
	content := h.r.MessageContent()
	if err := msg.UnmarshalContent(content); err != nil {
		return h.abort(err, msg.From)
	}

	// process message
	if err := h.r.ProcessMessage(msg.From, content); err != nil {
		return h.abort(err, msg.From)
	}
	return nil
}

func (h *Handler) finishRound() error {
	// get new messages
	nextRound, err := h.r.Finalize(h.outChan)
	if err != nil {
		return h.abort(err, "")
	}

	// a nil round indicates we have reached the final round
	if finalRound, ok := nextRound.(*round.Output); ok {
		h.result = finalRound.Result
		h.r = nil
		if h.result == nil && h.err == nil {
			h.err = Error{
				RoundNumber: h.roundNumber(),
				Culprit:     "",
				Err:         errors.New("failed without error before reaching the final round"),
			}
		}
		h.stop()
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

	for _, msg := range h.queue.Get(h.roundNumber()) {
		if err := h.handleMessage(msg); err != nil {
			return err
		}
	}

	if h.receivedAll() {
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

// abort wraps a Round error with information about the current round and a possible culprit.
func (h *Handler) abort(err error, culprit party.ID) error {
	roundErr := Error{
		RoundNumber: h.roundNumber(),
		Culprit:     culprit,
		Err:         err,
	}
	if h.err == nil {
		h.err = roundErr
	}

	return roundErr
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
