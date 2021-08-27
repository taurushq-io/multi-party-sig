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

type CorreOTSendSetup struct {
	_Delta   [params.SecBytes]byte
	_K_Delta [params.SecParam][params.SecBytes]byte
}

type CorreOTSetupSender struct {
	// After setup
	pl                *pool.Pool
	hash              *hash.Hash
	setup             *RandomOTReceiveSetup
	_Delta            [params.SecBytes]byte
	randomOTReceivers [params.SecParam]RandomOTReceiever
}

func NewCorreOTSetupSender(pl *pool.Pool, hash *hash.Hash) *CorreOTSetupSender {
	return &CorreOTSetupSender{pl: pl, hash: hash}
}

type CorreOTSetupSendRound1Message struct {
	msgs [params.SecParam]RandomOTReceiveRound1Message
}

func (r *CorreOTSetupSender) Round1(msg *CorreOTSetupReceiveRound1Message) (*CorreOTSetupSendRound1Message, error) {
	var err error
	r.setup, err = RandomOTSetupReceive(r.hash, &msg.msg)
	if err != nil {
		return nil, err
	}

	_, _ = rand.Read(r._Delta[:])

	randomOTNonces := r.hash.Fork(&hash.BytesWithDomain{
		TheDomain: "CorreOT Random OT Nonces",
		Bytes:     nil,
	}).Digest()
	for i := 0; i < params.SecParam; i++ {
		choice := safenum.Choice((r._Delta[i>>3] >> (i & 0b111)) & 1)
		nonce := make([]byte, 32)
		_, _ = randomOTNonces.Read(nonce)
		r.randomOTReceivers[i] = NewRandomOTReceiver(nonce, r.setup, choice)
	}

	outMsg := new(CorreOTSetupSendRound1Message)
	errors := r.pl.Parallelize(params.SecParam, func(i int) interface{} {
		var err error
		outMsg.msgs[i], err = r.randomOTReceivers[i].Round1()
		return err
	})
	for _, err := range errors {
		if err != nil {
			return outMsg, err.(error)
		}
	}

	return outMsg, nil
}

type CorreOTSetupSendRound2Message struct {
	msgs [params.SecParam]RandomOTReceiveRound2Message
}

func (r *CorreOTSetupSender) Round2(msg *CorreOTSetupReceiveRound2Message) *CorreOTSetupSendRound2Message {
	outMsg := new(CorreOTSetupSendRound2Message)
	for i := 0; i < params.SecParam; i++ {
		outMsg.msgs[i] = r.randomOTReceivers[i].Round2(&msg.msgs[i])
	}
	return outMsg
}

func (r *CorreOTSetupSender) Round3(msg *CorreOTSetupReceiveRound3Message) (*CorreOTSendSetup, error) {
	setup := new(CorreOTSendSetup)
	setup._Delta = r._Delta
	var err error
	for i := 0; i < params.SecParam; i++ {
		setup._K_Delta[i], err = r.randomOTReceivers[i].Round3(&msg.msgs[i])
		if err != nil {
			return nil, err
		}
	}
	return setup, nil
}

type CorreOTReceiveSetup struct {
	_K_0 [params.SecParam][params.SecBytes]byte
	_K_1 [params.SecParam][params.SecBytes]byte
}

type CorreOTSetupReceiver struct {
	// After setup
	pl              *pool.Pool
	hash            *hash.Hash
	group           curve.Curve
	setup           *RandomOTSendSetup
	randomOTSenders [params.SecParam]RandomOTSender
}

func NewCorreOTSetupReceive(pl *pool.Pool, hash *hash.Hash, group curve.Curve) *CorreOTSetupReceiver {
	return &CorreOTSetupReceiver{pl: pl, hash: hash, group: group}
}

type CorreOTSetupReceiveRound1Message struct {
	msg RandomOTSetupSendMessage
}

func (r *CorreOTSetupReceiver) Round1() *CorreOTSetupReceiveRound1Message {
	msg, setup := RandomOTSetupSend(r.hash, r.group)
	r.setup = setup

	randomOTNonces := r.hash.Fork(&hash.BytesWithDomain{
		TheDomain: "CorreOT Random OT Nonces",
		Bytes:     nil,
	}).Digest()
	for i := 0; i < params.SecParam; i++ {
		nonce := make([]byte, 32)
		_, _ = randomOTNonces.Read(nonce)
		r.randomOTSenders[i] = NewRandomOTSender(nonce, r.setup)
	}

	return &CorreOTSetupReceiveRound1Message{*msg}
}

type CorreOTSetupReceiveRound2Message struct {
	msgs [params.SecParam]RandomOTSendRound1Message
}

func (r *CorreOTSetupReceiver) Round2(msg *CorreOTSetupSendRound1Message) (*CorreOTSetupReceiveRound2Message, error) {
	outMsg := new(CorreOTSetupReceiveRound2Message)

	errors := r.pl.Parallelize(params.SecParam, func(i int) interface{} {
		var err error
		outMsg.msgs[i], err = r.randomOTSenders[i].Round1(&msg.msgs[i])
		return err
	})
	for _, err := range errors {
		if err != nil {
			return outMsg, err.(error)
		}
	}
	return outMsg, nil
}

type CorreOTSetupReceiveRound3Message struct {
	msgs [params.SecParam]RandomOTSendRound2Message
}

func (r *CorreOTSetupReceiver) Round3(msg *CorreOTSetupSendRound2Message) (*CorreOTSetupReceiveRound3Message, *CorreOTReceiveSetup, error) {
	outMsg := new(CorreOTSetupReceiveRound3Message)
	setup := new(CorreOTReceiveSetup)
	for i := 0; i < params.SecParam; i++ {
		msgsi, resultsi, err := r.randomOTSenders[i].Round2(&msg.msgs[i])
		if err != nil {
			return nil, nil, err
		}
		outMsg.msgs[i] = msgsi
		setup._K_0[i] = resultsi.Rand0
		setup._K_1[i] = resultsi.Rand1
	}
	return outMsg, setup, nil
}

func transposeBits(l int, M *[params.SecParam][]byte) [][params.SecBytes]byte {
	// TODO: Make this faster
	MT := make([][params.SecBytes]byte, l)
	for i := 0; i < l; i++ {
		for j := 0; j < params.SecParam; j++ {
			MT[i][j>>3] |= ((M[j][i>>3] >> (i & 0b111)) & 1) << (j & 0b111)
		}
	}
	return MT
}

type CorreOTSendResult struct {
	_Q [][params.SecBytes]byte
}

func CorreOTSend(ctxHash *hash.Hash, setup *CorreOTSendSetup, batchSize int, msg *CorreOTReceiveMessage) (*CorreOTSendResult, error) {
	batchSizeBytes := batchSize >> 3

	// Doing a keyed hash for our PRG is faster than cloning a forked hash many times
	prgKey := make([]byte, 32)
	_, _ = ctxHash.Fork(&hash.BytesWithDomain{TheDomain: "CorreOT PRG Key", Bytes: nil}).Digest().Read(prgKey)
	prg, _ := blake3.NewKeyed(prgKey)

	var Q [params.SecParam][]byte
	for i := 0; i < params.SecParam; i++ {
		if len(msg._U[i]) != batchSizeBytes {
			return nil, errors.New("CorreOTSend: incorrect batch size in message")
		}

		// Set Q to TDelta initially
		prg.Reset()
		_, _ = prg.Write(setup._K_Delta[i][:])
		Q[i] = make([]byte, batchSizeBytes)
		_, _ = prg.Digest().Read(Q[i])

		mask := -((setup._Delta[i>>3] >> (i & 0b111)) & 1)
		for j := 0; j < batchSizeBytes; j++ {
			Q[i][j] ^= mask & msg._U[i][j]
		}
	}

	return &CorreOTSendResult{_Q: transposeBits(batchSize, &Q)}, nil
}

type CorreOTReceiveMessage struct {
	_U [params.SecParam][]byte
}

type CorreOTReceiveResult struct {
	_T [][params.SecBytes]byte
}

func CorreOTReceive(ctxHash *hash.Hash, setup *CorreOTReceiveSetup, choices []byte) (*CorreOTReceiveMessage, *CorreOTReceiveResult) {
	batchSizeBytes := len(choices)

	// Doing a keyed hash for our PRG is faster than cloning a forked hash many times
	prgKey := make([]byte, 32)
	_, _ = ctxHash.Fork(&hash.BytesWithDomain{TheDomain: "CorreOT PRG Key", Bytes: nil}).Digest().Read(prgKey)
	prg, _ := blake3.NewKeyed(prgKey)

	outMsg := new(CorreOTReceiveMessage)
	var T0, T1 [params.SecParam][]byte
	for i := 0; i < params.SecParam; i++ {
		prg.Reset()
		_, _ = prg.Write(setup._K_0[i][:])
		T0[i] = make([]byte, batchSizeBytes)
		_, _ = prg.Digest().Read(T0[i])

		prg.Reset()
		_, _ = prg.Write(setup._K_1[i][:])
		T1[i] = make([]byte, batchSizeBytes)
		_, _ = prg.Digest().Read(T1[i])

		outMsg._U[i] = make([]byte, batchSizeBytes)
		for j := 0; j < batchSizeBytes; j++ {
			outMsg._U[i][j] = T0[i][j] ^ T1[i][j] ^ choices[j]
		}
	}

	return outMsg, &CorreOTReceiveResult{_T: transposeBits(8*batchSizeBytes, &T0)}
}
