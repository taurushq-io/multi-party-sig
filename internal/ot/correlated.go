package ot

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

type CorreOTSendSetup struct {
	_Delta   [params.SecBytes]byte
	_K_Delta [params.SecParam][params.SecBytes]byte
}

type CorreOTSetupSender struct {
	// After setup
	hash              *hash.Hash
	setup             *RandomOTReceiveSetup
	_Delta            [params.SecBytes]byte
	randomOTReceivers [params.SecParam]RandomOTReceiever
}

func NewCorreOTSetupSender(hash *hash.Hash) *CorreOTSetupSender {
	return &CorreOTSetupSender{hash: hash}
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

	var ctr [8]byte
	for i := 0; i < params.SecParam; i++ {
		choice := safenum.Choice((r._Delta[i>>3] >> (i & 0b111)) & 1)
		binary.BigEndian.PutUint64(ctr[:], uint64(i))
		r.randomOTReceivers[i] = NewRandomOTReceiver(r.hash.Fork(&hash.BytesWithDomain{
			TheDomain: "CorreOT Random OT Counter",
			Bytes:     ctr[:],
		}), choice, r.setup)
	}

	outMsg := new(CorreOTSetupSendRound1Message)
	for i := 0; i < params.SecParam; i++ {
		outMsg.msgs[i], err = r.randomOTReceivers[i].Round1()
		if err != nil {
			return nil, err
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
	hash            *hash.Hash
	group           curve.Curve
	setup           *RandomOTSendSetup
	randomOTSenders [params.SecParam]RandomOTSender
}

func NewCorreOTSetupReceive(hash *hash.Hash, group curve.Curve) *CorreOTSetupReceiver {
	return &CorreOTSetupReceiver{hash: hash, group: group}
}

type CorreOTSetupReceiveRound1Message struct {
	msg RandomOTSetupSendMessage
}

func (r *CorreOTSetupReceiver) Round1() *CorreOTSetupReceiveRound1Message {
	msg, setup := RandomOTSetupSend(r.hash, r.group)
	r.setup = setup

	var ctr [8]byte
	for i := 0; i < params.SecParam; i++ {
		binary.BigEndian.PutUint64(ctr[:], uint64(i))
		r.randomOTSenders[i] = NewRandomOTSender(r.hash.Fork(&hash.BytesWithDomain{
			TheDomain: "CorreOT Random OT Counter",
			Bytes:     ctr[:],
		}), setup)
	}

	return &CorreOTSetupReceiveRound1Message{*msg}
}

type CorreOTSetupReceiveRound2Message struct {
	msgs [params.SecParam]RandomOTSendRound1Message
}

func (r *CorreOTSetupReceiver) Round2(msg *CorreOTSetupSendRound1Message) (*CorreOTSetupReceiveRound2Message, error) {
	outMsg := new(CorreOTSetupReceiveRound2Message)

	var err error
	for i := 0; i < params.SecParam; i++ {
		outMsg.msgs[i], err = r.randomOTSenders[i].Round1(&msg.msgs[i])
		if err != nil {
			return nil, err
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
