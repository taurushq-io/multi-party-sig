package ot

import (
	"crypto/rand"
	"errors"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/zeebo/blake3"
)

// CorreOTSendSetup contains the results of the Sender's setup of a Correlated OT.
type CorreOTSendSetup struct {
	// The choice bits of the correlation.
	_Delta [params.OTBytes]byte
	// Each column of this matrix is taken from one of the Receiver's corresponding
	// columns, based on the corresponding bit of Delta.
	_K_Delta [params.OTParam][params.OTBytes]byte
}

// CorreOTSetupSender contains all of the state to run the Sender's setup of a Correlated OT.
//
// This struct is needed, because there are multiple rounds in the setup.
type CorreOTSetupSender struct {
	// After setup
	pl   *pool.Pool
	hash *hash.Hash
	// After Round 1
	// The setup which can be used for the different Random OTs.
	setup *RandomOTReceiveSetup
	// The correlation vector, sampled at random.
	_Delta [params.OTBytes]byte
	// We do multiple Random OTs, and each of them needs a receiver.
	randomOTReceivers [params.OTParam]RandomOTReceiever
}

// NewCorreOTSetupSender initializes the state for setting up the Sender part of a Correlated OT.
//
// This follows the Initialize part of Figure 3, in https://eprint.iacr.org/2015/546.
func NewCorreOTSetupSender(pl *pool.Pool, hash *hash.Hash) *CorreOTSetupSender {
	return &CorreOTSetupSender{pl: pl, hash: hash}
}

// CorreOTSetupSendRound1Message is the first message sent by the Sender in the Correlated OT setup.
type CorreOTSetupSendRound1Message struct {
	// We have to forward all the messages for the underlying Random OT instances.
	Msgs [params.OTParam]RandomOTReceiveRound1Message
}

// Round1 executes the Sender's first round of the Correlated OT setup.
func (r *CorreOTSetupSender) Round1(msg *CorreOTSetupReceiveRound1Message) (*CorreOTSetupSendRound1Message, error) {
	var err error
	r.setup, err = RandomOTSetupReceive(r.hash, &msg.Msg)
	if err != nil {
		return nil, err
	}

	_, _ = rand.Read(r._Delta[:])

	randomOTNonces := r.hash.Fork(&hash.BytesWithDomain{
		TheDomain: "CorreOT Random OT Nonces",
		Bytes:     nil,
	}).Digest()
	for i := 0; i < params.OTParam; i++ {
		choice := safenum.Choice(bitAt(i, r._Delta[:]))
		nonce := make([]byte, 32)
		_, _ = randomOTNonces.Read(nonce)
		r.randomOTReceivers[i] = NewRandomOTReceiver(nonce, r.setup, choice)
	}

	outMsg := new(CorreOTSetupSendRound1Message)
	errors := r.pl.Parallelize(params.OTParam, func(i int) interface{} {
		var err error
		outMsg.Msgs[i], err = r.randomOTReceivers[i].Round1()
		return err
	})
	for _, err := range errors {
		if err != nil {
			return outMsg, err.(error)
		}
	}

	return outMsg, nil
}

// CorreOTSetupSendRound1Message is the second message sent by the Sender in the Correlated OT setup.
type CorreOTSetupSendRound2Message struct {
	Msgs [params.OTParam]RandomOTReceiveRound2Message
}

// Round2 executes the Sender's second round of the Correlated OT setup.
func (r *CorreOTSetupSender) Round2(msg *CorreOTSetupReceiveRound2Message) *CorreOTSetupSendRound2Message {
	outMsg := new(CorreOTSetupSendRound2Message)
	for i := 0; i < params.OTParam; i++ {
		outMsg.Msgs[i] = r.randomOTReceivers[i].Round2(&msg.Msgs[i])
	}
	return outMsg
}

// Round2 executes the Sender's final round of the Correlated OT setup.
func (r *CorreOTSetupSender) Round3(msg *CorreOTSetupReceiveRound3Message) (*CorreOTSendSetup, error) {
	setup := new(CorreOTSendSetup)
	setup._Delta = r._Delta
	var err error
	for i := 0; i < params.OTParam; i++ {
		setup._K_Delta[i], err = r.randomOTReceivers[i].Round3(&msg.Msgs[i])
		if err != nil {
			return nil, err
		}
	}
	return setup, nil
}

// CorreOTReceiveSetup is the result of the Receiver's part of the Correlated OT setup.
//
// The Receiver gets two random matrices, and they know that the Sender has a
// striping of their columns, based on their correlation vector.
type CorreOTReceiveSetup struct {
	_K_0 [params.OTParam][params.OTBytes]byte
	_K_1 [params.OTParam][params.OTBytes]byte
}

// CorreOTSetupReceiver holds the Receiver's state on a Correlated OT Setup.
//
// This is necessary, because the setup process takes multiple rounds.
type CorreOTSetupReceiver struct {
	// After setup
	pl    *pool.Pool
	hash  *hash.Hash
	group curve.Curve
	// After round 1
	// The setup we use to create further Random OT instances.
	setup *RandomOTSendSetup
	// We need to keep the state for each instance.
	randomOTSenders [params.OTParam]RandomOTSender
}

// NewCorreOTSetupReceiver initializes the state for setting up the Receiver part of a Correlated OT.
//
// This follows the Initialize part of Figure 3, in https://eprint.iacr.org/2015/546.
func NewCorreOTSetupReceiver(pl *pool.Pool, hash *hash.Hash, group curve.Curve) *CorreOTSetupReceiver {
	return &CorreOTSetupReceiver{pl: pl, hash: hash, group: group}
}

// CorreOTSetupReceiveRound1Message is the first message sent by the Receiver in a Correlated OT Setup.
type CorreOTSetupReceiveRound1Message struct {
	Msg RandomOTSetupSendMessage
}

// EmptyCorreOTSetupReceiveRound1Message initializes a message with a given group, so that it can be unmarshalled.
func EmptyCorreOTSetupReceiveRound1Message(group curve.Curve) *CorreOTSetupReceiveRound1Message {
	return &CorreOTSetupReceiveRound1Message{Msg: *EmptyRandomOTSetupSendMessage(group)}
}

// Round1 runs the first round of a Receiver's correlated OT Setup.
func (r *CorreOTSetupReceiver) Round1() *CorreOTSetupReceiveRound1Message {
	msg, setup := RandomOTSetupSend(r.hash, r.group)
	r.setup = setup

	randomOTNonces := r.hash.Fork(&hash.BytesWithDomain{
		TheDomain: "CorreOT Random OT Nonces",
		Bytes:     nil,
	}).Digest()
	for i := 0; i < params.OTParam; i++ {
		nonce := make([]byte, 32)
		_, _ = randomOTNonces.Read(nonce)
		r.randomOTSenders[i] = NewRandomOTSender(nonce, r.setup)
	}

	return &CorreOTSetupReceiveRound1Message{*msg}
}

// CorreOTSetupReceiveRound1Message is the second message sent by the Receiver in a Correlated OT Setup.
type CorreOTSetupReceiveRound2Message struct {
	Msgs [params.OTParam]RandomOTSendRound1Message
}

// Round1 runs the second round of a Receiver's correlated OT Setup.
func (r *CorreOTSetupReceiver) Round2(msg *CorreOTSetupSendRound1Message) (*CorreOTSetupReceiveRound2Message, error) {
	outMsg := new(CorreOTSetupReceiveRound2Message)

	errors := r.pl.Parallelize(params.OTParam, func(i int) interface{} {
		var err error
		outMsg.Msgs[i], err = r.randomOTSenders[i].Round1(&msg.Msgs[i])
		return err
	})
	for _, err := range errors {
		if err != nil {
			return outMsg, err.(error)
		}
	}
	return outMsg, nil
}

// CorreOTSetupReceiveRound1Message is the third message sent by the Receiver in a Correlated OT Setup.
type CorreOTSetupReceiveRound3Message struct {
	Msgs [params.OTParam]RandomOTSendRound2Message
}

// Round1 runs the third round of a Receiver's correlated OT Setup.
func (r *CorreOTSetupReceiver) Round3(msg *CorreOTSetupSendRound2Message) (*CorreOTSetupReceiveRound3Message, *CorreOTReceiveSetup, error) {
	outMsg := new(CorreOTSetupReceiveRound3Message)
	setup := new(CorreOTReceiveSetup)
	for i := 0; i < params.OTParam; i++ {
		msgsi, resultsi, err := r.randomOTSenders[i].Round2(&msg.Msgs[i])
		if err != nil {
			return nil, nil, err
		}
		outMsg.Msgs[i] = msgsi
		setup._K_0[i] = resultsi.Rand0
		setup._K_1[i] = resultsi.Rand1
	}
	return outMsg, setup, nil
}

// transposeBits transpose a matrix of bits.
//
// l is the number of elements in each row of the original matrix.
func transposeBits(l int, M *[params.OTParam][]byte) [][params.OTBytes]byte {
	// TODO: Make this faster
	MT := make([][params.OTBytes]byte, l)
	for i := 0; i < l; i++ {
		for j := 0; j < params.OTParam; j++ {
			MT[i][j>>3] |= bitAt(i, M[j]) << (j & 0b111)
		}
	}
	return MT
}

// CorreOTSendResult is the Sender's result after executing the Correlated OT protocol.
type CorreOTSendResult struct {
	// The columns of the U matrix from the protocol. This is included to be able
	// to hash later, which we use for the random check weights.
	_U [params.OTParam][]byte
	// The rows of the Q matrix from the protocol.
	_Q [][params.OTBytes]byte
}

// CorreOTSend runs the Sender's end of the Correlated OT protocol.
//
// The Sender will get binary vectors q_j, and the Receiver will get vectors t_j
// satsifying t_j = q_j ^ (choices_j * Delta).
//
// This follows the extend section of Figure 3 in https://eprint.iacr.org/2015/546.
//
// A single setup can be used for multiple runs of the protocol, but it's important
// that ctxHash be initialized with some kind of nonce in that case.
func CorreOTSend(ctxHash *hash.Hash, setup *CorreOTSendSetup, batchSize int, msg *CorreOTReceiveMessage) (*CorreOTSendResult, error) {
	batchSizeBytes := batchSize >> 3

	// Doing a keyed hash for our PRG is faster than cloning a forked hash many times
	prgKey := make([]byte, 32)
	_, _ = ctxHash.Fork(&hash.BytesWithDomain{TheDomain: "CorreOT PRG Key", Bytes: nil}).Digest().Read(prgKey)
	prg, _ := blake3.NewKeyed(prgKey)

	var Q [params.OTParam][]byte
	for i := 0; i < params.OTParam; i++ {
		if len(msg.U[i]) != batchSizeBytes {
			return nil, errors.New("CorreOTSend: incorrect batch size in message")
		}

		// Set Q to TDelta initially
		prg.Reset()
		_, _ = prg.Write(setup._K_Delta[i][:])
		Q[i] = make([]byte, batchSizeBytes)
		_, _ = prg.Digest().Read(Q[i])

		mask := -bitAt(i, setup._Delta[:])
		for j := 0; j < batchSizeBytes; j++ {
			Q[i][j] ^= mask & msg.U[i][j]
		}
	}

	return &CorreOTSendResult{_U: msg.U, _Q: transposeBits(batchSize, &Q)}, nil
}

// CorreOTReceiveMessage is the first message the Receiver sends to the Sender in the Correlated OT protocol.
type CorreOTReceiveMessage struct {
	// The columns of the U matrix from the paper.
	U [params.OTParam][]byte
}

// CorreOTReceiveResult is the Receiver's result at the end of the Correlated OT protocol.
type CorreOTReceiveResult struct {
	// The rows of the T matrix from the paper.
	_T [][params.OTBytes]byte
}

// CorreOTReceive runs the Receiver's end of the Correlated OT protocol.
//
// The Sender will get binary vectors q_j, and the Receiver will get vectors t_j
// satsifying t_j = q_j ^ (choices_j * Delta).
//
// This follows the extend section of Figure 3 in https://eprint.iacr.org/2015/546.
//
// A single setup can be used for multiple runs of the protocol, but it's important
// that ctxHash be initialized with some kind of nonce in that case.
func CorreOTReceive(ctxHash *hash.Hash, setup *CorreOTReceiveSetup, choices []byte) (*CorreOTReceiveMessage, *CorreOTReceiveResult) {
	batchSizeBytes := len(choices)

	// Doing a keyed hash for our PRG is faster than cloning a forked hash many times
	prgKey := make([]byte, 32)
	_, _ = ctxHash.Fork(&hash.BytesWithDomain{TheDomain: "CorreOT PRG Key", Bytes: nil}).Digest().Read(prgKey)
	prg, _ := blake3.NewKeyed(prgKey)

	outMsg := new(CorreOTReceiveMessage)
	var T0, T1 [params.OTParam][]byte
	for i := 0; i < params.OTParam; i++ {
		prg.Reset()
		_, _ = prg.Write(setup._K_0[i][:])
		T0[i] = make([]byte, batchSizeBytes)
		_, _ = prg.Digest().Read(T0[i])

		prg.Reset()
		_, _ = prg.Write(setup._K_1[i][:])
		T1[i] = make([]byte, batchSizeBytes)
		_, _ = prg.Digest().Read(T1[i])

		outMsg.U[i] = make([]byte, batchSizeBytes)
		for j := 0; j < batchSizeBytes; j++ {
			outMsg.U[i][j] = T0[i][j] ^ T1[i][j] ^ choices[j]
		}
	}

	return outMsg, &CorreOTReceiveResult{_T: transposeBits(8*batchSizeBytes, &T0)}
}
