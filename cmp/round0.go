package cmp

import (
	"errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/taurusgroup/cmp-ecdsa/paillier"
	"go.dedis.ch/kyber/v3"
	"sync"
)

type round struct {
	// selfID is our own ID
	selfID int
	// otherIDs contains the IDs of other parties, but not our own
	otherIDs []int

	// parties is a contains all values released publicly by all parties
	// including ourselves.
	parties map[int]*signParty

	// msg1, ..., sigs store the messages temporarily, until the appropriate round can process them
	msgs1 map[int]msg1
	msgs2 map[int]msg2
	msgs3 map[int]msg3
	msgs4 map[int]msg4
	sigs  map[int]Signature

	group   Suite
	message kyber.Scalar // m

	secret *PartySecret // x_i

	// Round1
	k             kyber.Scalar
	gamma         kyber.Scalar
	kEncNonce     *paillier.Nonce
	gammaEncNonce *paillier.Nonce

	// Round3
	chi   kyber.Scalar // 𝟀_i (share)
	Gamma kyber.Point  // 𝞒

	// Round4
	R kyber.Point // R = 𝞭^-1 • 𝞒

	// Output
	sigma      kyber.Scalar // 𝞂 = km + r 𝟀
	sig        *Signature   // S = (r,s)
	completion func()

	// number is the current round
	number int

	// log is a logger for debug info
	log zerolog.Logger

	// Debug contains timings of each round
	debug Debug

	sync.Mutex
}

func NewRound(config *Config, completion func()) Round {
	if config == nil {
		return nil
	}

	partyCount := len(config.Parties)

	otherParties := make([]int, 0, partyCount-1)

	r := &round{
		selfID:     config.ID,
		parties:    make(map[int]*signParty, partyCount),
		secret:     config.Secret,
		group:      suite,
		number:     1,
		msgs1:      make(map[int]msg1, partyCount-1),
		msgs2:      make(map[int]msg2, partyCount-1),
		msgs3:      make(map[int]msg3, partyCount-1),
		msgs4:      make(map[int]msg4, partyCount-1),
		sigs:       make(map[int]Signature, partyCount-1),
		completion: completion,
		log:        log.Logger.With().Int("party", config.ID).Int("round", 1).Logger(),
		debug: Debug{
			N:  partyCount,
			ID: config.ID,
		},
	}

	for _, p := range config.Parties {
		if p.ID != config.ID {
			otherParties = append(otherParties, p.ID)
		}

		r.parties[p.ID] = &signParty{
			Party: p,
		}
	}

	r.otherIDs = otherParties

	r.log = r.log.With().Int("round", 1).Logger()
	return &round1{
		round: r,
	}
}

// Number returns the round number. It is defined as the moments between message outputs.
func (r *round) Number() int {
	return r.number
}

// IsFinal indicates whether we are in the round where the signature can be acquired.
func (r *round) IsFinal() bool {
	return r.number == 5
}

// Store analyzes the message and determines whether it should be saved. For a future round
// It checks to see if the message is intended for the current or future round, and that
// this party is the correct receiver. Otherwise, the message is dropped.
//
// This function is blocking. A round will only process one message at a time.
func (r *round) Store(message *Message) error {
	r.Lock()
	defer r.Unlock()

	if message.Message != "" && r.message == nil {
		r.message = HashMessageToScalar([]byte(message.Message))
		r.Log().Info().Str("m", message.Message).Msg("Starting Signing Protocol")
	}

	// Ignore messages not addressed to us
	if message.To != r.selfID || message.From == r.selfID {
		return nil
	}

	if message.Msg1 != nil {
		if _, ok := r.msgs1[message.From]; ok {
			return errors.New("msg1 already received")
		}
		r.msgs1[message.From] = *message.Msg1
		return nil
	}
	if message.Msg2 != nil {
		if _, ok := r.msgs2[message.From]; ok {
			return errors.New("msg2 already received")
		}
		r.msgs2[message.From] = *message.Msg2
		return nil
	}
	if message.Msg3 != nil {
		if _, ok := r.msgs3[message.From]; ok {
			return errors.New("msg3 already received")
		}
		r.msgs3[message.From] = *message.Msg3
		return nil
	}
	if message.Msg4 != nil {
		if _, ok := r.msgs4[message.From]; ok {
			return errors.New("msg4 already received")
		}
		r.msgs4[message.From] = *message.Msg4
		return nil
	}

	if message.Signature != nil {
		if _, ok := r.sigs[message.From]; ok {
			return errors.New("sigs already received")
		}
		r.sigs[message.From] = *message.Signature
		return nil
	}
	return nil
}

// CanExecute verifies that we have received a message from every other party during this round.
// The function is blocking.
//
// It is the blocking version of canExecute
func (r *round) CanExecute() bool {
	r.Lock()
	defer r.Unlock()

	return r.canExecute()
}

// canExecute verifies that we have received a message from every other party during this round.
func (r *round) canExecute() bool {

	required := len(r.otherIDs)

	switch r.Number() {
	case 1:
		return r.message != nil
	case 2:
		return len(r.msgs1) == required
	case 3:
		return len(r.msgs2) == required
	case 4:
		return len(r.msgs3) == required
	case 5:
		return len(r.msgs4) == required

	default:
		return false

	}
}

func (r *round) Signature() *Signature {
	return nil
}

func (r *round) Log() *zerolog.Logger {
	return &r.log
}

func (r *round) GetMessagesOut() ([]*Message, error) {
	return nil, nil
}

func (r *round) NextRound() Round {
	return r
}

func (r *round) SetCompletion(f func()) {
	r.completion = f
}

func (r *round) Debug() Debug {
	return r.debug
}
