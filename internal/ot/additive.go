package ot

import (
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/zeebo/blake3"
)

type AdditiveOTSendRound1Message struct {
	CombinedPads [][2]curve.Scalar
}

type AdditiveOTSendResult [][2]curve.Scalar

type AdditiveOTSender struct {
	ctxHash   *hash.Hash
	setup     *CorreOTSendSetup
	batchSize int
	group     curve.Curve
	alpha     [2]curve.Scalar
}

func NewAdditiveOTSender(ctxHash *hash.Hash, setup *CorreOTSendSetup, batchSize int, alpha [2]curve.Scalar) *AdditiveOTSender {
	return &AdditiveOTSender{
		ctxHash:   ctxHash,
		setup:     setup,
		batchSize: batchSize,
		group:     alpha[0].Curve(),
		alpha:     alpha,
	}
}

func (r *AdditiveOTSender) Round1(msg *AdditiveOTReceiveRound1Message) (*AdditiveOTSendRound1Message, AdditiveOTSendResult, error) {
	extendedResult, err := ExtendedOTSend(r.ctxHash, r.setup, r.batchSize, msg.msg)
	if err != nil {
		return nil, nil, err
	}
	prg := blake3.New()
	outMsg := new(AdditiveOTSendRound1Message)
	outMsg.CombinedPads = make([][2]curve.Scalar, r.batchSize)
	result := make([][2]curve.Scalar, r.batchSize)
	for i := 0; i < r.batchSize; i++ {
		prg.Reset()
		_, _ = prg.Write(extendedResult._V0[i][:])
		digest := prg.Digest()
		result[i][0] = sample.Scalar(digest, r.group)
		result[i][1] = sample.Scalar(digest, r.group)

		prg.Reset()
		_, _ = prg.Write(extendedResult._V0[i][:])
		digest = prg.Digest()
		outMsg.CombinedPads[i][0] = sample.Scalar(digest, r.group)
		outMsg.CombinedPads[i][1] = sample.Scalar(digest, r.group)

		outMsg.CombinedPads[i][0].Add(result[i][0]).Add(r.alpha[0])
		outMsg.CombinedPads[i][1].Add(result[i][1]).Add(r.alpha[1])
	}
	return outMsg, result, nil
}

type AdditiveOTReceiver struct {
	// After setup
	ctxHash *hash.Hash
	setup   *CorreOTReceiveSetup
	choices []byte
	group   curve.Curve
	// After round 1
	result *ExtendedOTReceiveResult
}

func NewAdditiveOTReceiver(ctxHash *hash.Hash, setup *CorreOTReceiveSetup, group curve.Curve, choices []byte) *AdditiveOTReceiver {
	return &AdditiveOTReceiver{ctxHash: ctxHash, setup: setup, group: group, choices: choices}
}

type AdditiveOTReceiveRound1Message struct {
	msg *ExtendedOTReceiveMessage
}

func (r *AdditiveOTReceiver) Round1() *AdditiveOTReceiveRound1Message {
	msg, result := ExtendedOTReceive(r.ctxHash, r.setup, r.choices)
	r.result = result
	return &AdditiveOTReceiveRound1Message{msg: msg}
}

type AdditiveOTReceiveResult [][2]curve.Scalar

func (r *AdditiveOTReceiver) Round2(msg *AdditiveOTSendRound1Message) AdditiveOTReceiveResult {
	batchSize := 8 * len(r.choices)
	result := make([][2]curve.Scalar, batchSize)
	prg := blake3.New()
	var pad [2]curve.Scalar
	for i := 0; i < batchSize; i++ {
		choice := ((r.choices[i>>3] >> (i & 0b111)) & 1) == 1
		prg.Reset()
		_, _ = prg.Write(r.result._VChoices[i][:])
		digest := prg.Digest()
		pad[0] = sample.Scalar(digest, r.group)
		pad[1] = sample.Scalar(digest, r.group)
		if choice {
			result[i] = msg.CombinedPads[i]
			result[i][0].Sub(pad[0])
			result[i][1].Sub(pad[1])
		} else {
			result[i] = pad
		}
	}
	return result
}
