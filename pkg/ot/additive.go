package ot

import (
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/zeebo/blake3"
)

// AdditiveOTSendRound1Message is the first message by the Sender in the Additive OT protocol.
type AdditiveOTSendRound1Message struct {
	CombinedPads [][2][]byte
}

// AdditiveOTSendResult is the result of running the Additive OT protocol.
//
// The sender receives a collection of random pads.
type AdditiveOTSendResult [][2]curve.Scalar

// AdditiveOTSender holds the Sender's state for the Additive OT Protocol.
type AdditiveOTSender struct {
	ctxHash *hash.Hash
	group   curve.Curve
	// The setup used for the underlying correlated OT.
	setup *CorreOTSendSetup
	// The number of transfers to perform
	batchSize int
	// The constant adjust that will be conditionally added to the pads.
	alpha [2]curve.Scalar
}

// NewAdditiveOTSender initializes the sender of an Additive OT.
//
// This follows Protocol 9 of https://eprint.iacr.org/2018/499 to a certain extent.
// The main difference is that we strictly conform to the underlying extended OT,
// removing Doerner's modifications to the check.
//
// The goal of this protocol is for the Sender to learn random pads, each pad being two scalars,
// and for the Receiver to receive choice_j * alpha_j - pad_j for each of the pads, and their choices.
//
// A single setup can be used for multiple protocol executions, but should be initialized with a nonce.
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
	extendedResult, err := ExtendedOTSend(r.ctxHash, r.setup, r.batchSize, msg.Msg)
	if err != nil {
		return nil, nil, err
	}
	prg := blake3.New()
	outMsg := new(AdditiveOTSendRound1Message)
	outMsg.CombinedPads = make([][2][]byte, r.batchSize)
	result := make([][2]curve.Scalar, r.batchSize)
	var combinedPads [2]curve.Scalar
	for i := 0; i < r.batchSize; i++ {
		prg.Reset()
		_, _ = prg.Write(extendedResult._V0[i][:])
		digest := prg.Digest()
		result[i][0] = sample.Scalar(digest, r.group)
		result[i][1] = sample.Scalar(digest, r.group)

		prg.Reset()
		_, _ = prg.Write(extendedResult._V1[i][:])
		digest = prg.Digest()
		combinedPads[0] = sample.Scalar(digest, r.group)
		combinedPads[1] = sample.Scalar(digest, r.group)

		combinedPads[0].Sub(result[i][0]).Add(r.alpha[0])
		combinedPads[1].Sub(result[i][1]).Add(r.alpha[1])

		var err error
		outMsg.CombinedPads[i][0], err = combinedPads[0].MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		outMsg.CombinedPads[i][1], err = combinedPads[1].MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
	}
	return outMsg, result, nil
}

// AdditiveOTReceiver holds the Receiver's state for the Additive OT Protocol.
type AdditiveOTReceiver struct {
	// After setup
	ctxHash *hash.Hash
	group   curve.Curve
	setup   *CorreOTReceiveSetup
	choices []byte
	// After round 1
	result *ExtendedOTReceiveResult
}

// NewAdditiveOTReceiver initializes the receiver of an Additive OT.
//
// This follows Protocol 9 of https://eprint.iacr.org/2018/499 to a certain extent.
// The main difference is that we strictly conform to the underlying extended OT,
// removing Doerner's modifications to the check.
//
// The goal of this protocol is for the Sender to learn random pads, each pad being two scalars,
// and for the Receiver to receive choice_j * alpha_j - pad_j for each of the pads, and their choices.
//
// A single setup can be used for multiple protocol executions, but should be initialized with a nonce.
func NewAdditiveOTReceiver(ctxHash *hash.Hash, setup *CorreOTReceiveSetup, group curve.Curve, choices []byte) *AdditiveOTReceiver {
	return &AdditiveOTReceiver{ctxHash: ctxHash, setup: setup, group: group, choices: choices}
}

// AdditiveOTReceiveRound1Message is the first message sent by the Receiver in an Additive OT.
type AdditiveOTReceiveRound1Message struct {
	Msg *ExtendedOTReceiveMessage
}

// Round1 executes the Receiver's first round of an Additive OT.
func (r *AdditiveOTReceiver) Round1() *AdditiveOTReceiveRound1Message {
	msg, result := ExtendedOTReceive(r.ctxHash, r.setup, r.choices)
	r.result = result
	return &AdditiveOTReceiveRound1Message{Msg: msg}
}

// AdditiveOTReceiveResult is the Receiver's result for an Additive OT.
//
// For each choice_j, we receive choice_j * alpha - pad.
type AdditiveOTReceiveResult [][2]curve.Scalar

// Round2 executes the Receiver's second round of an Additive OT.
func (r *AdditiveOTReceiver) Round2(msg *AdditiveOTSendRound1Message) (AdditiveOTReceiveResult, error) {
	batchSize := 8 * len(r.choices)
	result := make([][2]curve.Scalar, batchSize)
	prg := blake3.New()
	for i := 0; i < batchSize; i++ {
		mask := -bitAt(i, r.choices)
		prg.Reset()
		_, _ = prg.Write(r.result._VChoices[i][:])
		digest := prg.Digest()
		result[i][0] = sample.Scalar(digest, r.group).Negate()
		result[i][1] = sample.Scalar(digest, r.group).Negate()
		for j := 0; j < len(msg.CombinedPads[j][0]); j++ {
			msg.CombinedPads[i][0][j] &= mask
		}
		for j := 0; j < len(msg.CombinedPads[j][1]); j++ {
			msg.CombinedPads[i][1][j] &= mask
		}
		combinedPad0 := r.group.NewScalar()
		if err := combinedPad0.UnmarshalBinary(msg.CombinedPads[i][0]); err != nil {
			return nil, err
		}
		combinedPad1 := r.group.NewScalar()
		if err := combinedPad1.UnmarshalBinary(msg.CombinedPads[i][1]); err != nil {
			return nil, err
		}
		result[i][0].Add(combinedPad0)
		result[i][1].Add(combinedPad1)
	}
	return result, nil
}
