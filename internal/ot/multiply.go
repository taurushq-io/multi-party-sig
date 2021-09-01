package ot

import (
	"crypto/rand"
	"errors"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

func scalarBytes(group curve.Curve) int {
	return (group.ScalarBits() + 7) & ^0b111
}

// encode converts a scalar to a sequence of bits, using a certain number of scalars for noise.
//
// The noise should be public, but the encoding will be unpredictable, but still decodable.
//
// The noise vector should have a length that's a multiple of 8
func encode(beta curve.Scalar, noise []curve.Scalar) ([]byte, error) {
	// This follows Algorithm 4 in Doerner's paper:
	//   https://eprint.iacr.org/2018/499
	group := beta.Curve()

	gamma := make([]byte, len(noise)/8)
	_, _ = rand.Read(gamma)

	acc := group.NewScalar().Set(beta)
	mulNat := new(safenum.Nat)
	mul := group.NewScalar()
	for i := 0; i < len(noise); i++ {
		mulNat.SetUint64(uint64((gamma[i>>3] >> (i & 0b111)) & 1))
		acc.Sub(mul.SetNat(mulNat).Mul(noise[i]))
	}

	data, err := acc.MarshalBinary()
	if err != nil {
		return nil, err
	}

	data = append(data, gamma...)
	return data, nil
}

func makeGadget(ctxHash *hash.Hash, group curve.Curve) []curve.Scalar {
	scalarEnd := scalarBytes(group)
	// We have space for all the bytes of a scalar, and then noise vectors, padded to a multiple of 8
	out := make([]curve.Scalar, 8*((group.ScalarBits()+7)/8+(group.ScalarBits()+2*params.StatParam+7)/8))
	// Handle powers of 2, in big endian order
	acc := group.NewScalar().SetNat(new(safenum.Nat).SetUint64(1))
	for i := scalarEnd - 1; i >= 0; i-- {
		out[i] = group.NewScalar().Set(acc)
		acc.Add(acc)
	}
	// Generate random noise
	digest := ctxHash.Fork(&hash.BytesWithDomain{TheDomain: "Multiply Gadget Sampling", Bytes: nil}).Digest()
	for i := scalarEnd; i < len(out); i++ {
		out[i] = sample.Scalar(digest, group)
	}
	return out
}

type MultiplySender struct {
	// After setup
	ctxHash     *hash.Hash
	group       curve.Curve
	setup       *CorreOTSendSetup
	doubleAlpha [2]curve.Scalar
	gadget      []curve.Scalar
	sender      *AdditiveOTSender
}

func NewMultiplySender(ctxHash *hash.Hash, setup *CorreOTSendSetup, alpha curve.Scalar) *MultiplySender {
	group := alpha.Curve()
	gadget := makeGadget(ctxHash, group)
	var doubleAlpha [2]curve.Scalar
	doubleAlpha[0] = alpha
	doubleAlpha[1] = sample.Scalar(rand.Reader, group)
	return &MultiplySender{
		ctxHash:     ctxHash,
		group:       group,
		setup:       setup,
		gadget:      gadget,
		doubleAlpha: doubleAlpha,
		sender:      NewAdditiveOTSender(ctxHash, setup, len(gadget), doubleAlpha),
	}
}

type MultiplySendRound1Message struct {
	msg    *AdditiveOTSendRound1Message
	rCheck []curve.Scalar
	uCheck curve.Scalar
}

func (r *MultiplySender) Round1(msg *MultiplyReceiveRound1Message) (*MultiplySendRound1Message, curve.Scalar, error) {
	additiveMsg, result, err := r.sender.Round1(msg.msg)
	if err != nil {
		return nil, nil, err
	}

	digest := r.ctxHash.Fork(&hash.BytesWithDomain{TheDomain: "Multiply Chi Sampling", Bytes: nil}).Digest()
	chi0 := sample.Scalar(digest, r.group)
	chi1 := sample.Scalar(digest, r.group)

	mul := r.group.NewScalar()

	uCheck := r.group.NewScalar()
	uCheck.Add(mul.Set(r.doubleAlpha[0]).Mul(chi0))
	uCheck.Add(mul.Set(r.doubleAlpha[1]).Mul(chi1))

	rCheck := make([]curve.Scalar, len(result))
	for i := 0; i < len(rCheck); i++ {
		rCheck[i] = r.group.NewScalar()
		rCheck[i].Add(mul.Set(result[i][0]).Mul(chi0))
		rCheck[i].Add(mul.Set(result[i][1]).Mul(chi1))
	}

	share := r.group.NewScalar()
	for i := 0; i < len(result); i++ {
		share.Add(mul.Set(result[i][0]).Mul(r.gadget[i]))
	}

	return &MultiplySendRound1Message{
		msg:    additiveMsg,
		rCheck: rCheck,
		uCheck: uCheck,
	}, share, nil
}

type MultiplyReceiver struct {
	// After setup
	ctxHash  *hash.Hash
	group    curve.Curve
	setup    *CorreOTReceiveSetup
	beta     curve.Scalar
	gadget   []curve.Scalar
	choices  []byte
	receiver *AdditiveOTReceiver
}

func NewMultiplyReceiver(ctxHash *hash.Hash, setup *CorreOTReceiveSetup, beta curve.Scalar) (*MultiplyReceiver, error) {
	group := beta.Curve()
	gadget := makeGadget(ctxHash, group)
	choices, err := encode(beta, gadget[scalarBytes(group):])
	if err != nil {
		return nil, err
	}
	return &MultiplyReceiver{
		ctxHash:  ctxHash,
		group:    group,
		setup:    setup,
		beta:     beta,
		gadget:   gadget,
		choices:  choices,
		receiver: NewAdditiveOTReceiver(ctxHash, setup, group, choices),
	}, nil
}

type MultiplyReceiveRound1Message struct {
	msg *AdditiveOTReceiveRound1Message
}

func (r *MultiplyReceiver) Round1() *MultiplyReceiveRound1Message {
	msg := r.receiver.Round1()
	return &MultiplyReceiveRound1Message{msg}
}

func (r *MultiplyReceiver) Round2(msg *MultiplySendRound1Message) (curve.Scalar, error) {
	result, err := r.receiver.Round2(msg.msg)
	if err != nil {
		return nil, err
	}

	digest := r.ctxHash.Fork(&hash.BytesWithDomain{TheDomain: "Multiply Chi Sampling", Bytes: nil}).Digest()
	chi0 := sample.Scalar(digest, r.group)
	chi1 := sample.Scalar(digest, r.group)

	mul := r.group.NewScalar()
	checkLeft := r.group.NewScalar()
	checkRight := r.group.NewScalar()
	choiceNat := new(safenum.Nat)

	for i := 0; i < len(result); i++ {
		checkLeft.Set(result[i][0]).Mul(chi0)
		checkLeft.Add(mul.Set(result[i][1]).Mul(chi1))

		checkRight.SetNat(choiceNat.SetUint64(uint64((r.choices[i>>3] >> (i & 0b111)) & 1)))
		checkRight.Mul(msg.uCheck)
		checkRight.Sub(msg.rCheck[i])

		if !checkLeft.Equal(checkRight) {
			return nil, errors.New("multiply receive round 2: integrity check failed")
		}
	}

	share := r.group.NewScalar()
	for i := 0; i < len(result); i++ {
		share.Add(mul.Set(result[i][0]).Mul(r.gadget[i]))
	}

	return share, nil
}
