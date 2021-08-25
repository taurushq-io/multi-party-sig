package ot

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
)

type RandomOTSetupSendMessage struct {
	_B      curve.Point
	_BProof *zksch.Proof
}

type RandomOTSetupSendResult struct {
	b  curve.Scalar
	_B curve.Point
}

func RandomOTSetupSend(hash *hash.Hash, group curve.Curve) (*RandomOTSetupSendMessage, *RandomOTSetupSendResult) {
	b := sample.Scalar(rand.Reader, group)
	B := b.ActOnBase()
	BProof := zksch.NewProof(hash, B, b)
	return &RandomOTSetupSendMessage{_B: B, _BProof: BProof}, &RandomOTSetupSendResult{_B: B, b: b}
}

type RandomOTSetupReceiveResult struct {
	_B curve.Point
}

func RandomOTSetupReceive(hash *hash.Hash, msg *RandomOTSetupSendMessage) (*RandomOTSetupReceiveResult, error) {
	if !msg._BProof.Verify(hash, msg._B) {
		return nil, fmt.Errorf("RandomOTSetupReceive: Schnorr proof failed to verify")
	}
	return &RandomOTSetupReceiveResult{_B: msg._B}, nil
}

type RandomOTReceiever struct {
	// After setup
	hash   *hash.Hash
	group  curve.Curve
	choice safenum.Choice
	_B     curve.Point
	// After Round1
	randChoice []byte
	// After Round2
	receivedChallenge []byte
	hh_randChoice     []byte
}

func NewRandomOTReceiver(hash *hash.Hash, choice safenum.Choice, result *RandomOTSetupReceiveResult) *RandomOTReceiever {
	return &RandomOTReceiever{hash: hash, group: result._B.Curve(), choice: choice, _B: result._B}
}

type RandomOTReceiveRound1Message struct {
	_A curve.Point
}

func (r *RandomOTReceiever) Round1() *RandomOTReceiveRound1Message {
	// We sample a <- Z_q, and then compute
	//   A = a * G + w * B
	//   pad_w = H(a * B)
	a := sample.Scalar(rand.Reader, r.group)
	A := a.ActOnBase()
	one := new(safenum.Nat).SetUint64(1)
	choiceScalar := r.group.NewScalar().SetNat(new(safenum.Nat).CondAssign(r.choice, one))
	A = A.Add(choiceScalar.Act(r._B))

	r.randChoice = make([]byte, params.SecBytes)
	_ = r.hash.WriteAny(a.Act(r._B))
	_, _ = r.hash.Digest().Read(r.randChoice)

	return &RandomOTReceiveRound1Message{_A: A}
}

type RandomOTReceiveRound2Message struct {
	response []byte
}

func (r *RandomOTReceiever) Round2(msg *RandomOTSendRound1Message) *RandomOTReceiveRound2Message {
	r.receivedChallenge = msg.challenge
	// response = H(H(randW)) ^ (w * challenge).
	response := make([]byte, len(msg.challenge))

	H := hash.New()
	_ = H.WriteAny(r.randChoice)
	_, _ = H.Digest().Read(response)
	H = hash.New()
	_ = H.WriteAny(response)
	_, _ = H.Digest().Read(response)

	r.hh_randChoice = make([]byte, len(response))
	copy(response, r.hh_randChoice)

	mask := -byte(r.choice)
	for i := 0; i < len(msg.challenge); i++ {
		response[i] ^= mask & msg.challenge[i]
	}

	return &RandomOTReceiveRound2Message{response: response}
}

func (r *RandomOTReceiever) Round3(msg *RandomOTSendRound2Message) ([]byte, error) {
	h_decommit0 := make([]byte, len(r.receivedChallenge))
	H := hash.New()
	_ = H.WriteAny(msg.decommit0)
	_, _ = H.Digest().Read(h_decommit0)

	h_decommit1 := make([]byte, len(r.receivedChallenge))
	H = hash.New()
	_ = H.WriteAny(msg.decommit1)
	_, _ = H.Digest().Read(h_decommit1)

	actualChallenge := make([]byte, len(r.receivedChallenge))
	for i := 0; i < len(r.receivedChallenge); i++ {
		actualChallenge[i] = h_decommit0[i] ^ h_decommit1[i]
	}

	if subtle.ConstantTimeCompare(r.receivedChallenge, actualChallenge) != 1 {
		return nil, fmt.Errorf("RandomOTReceive Round 3: incorrect decommitment")
	}

	// Assign the decommitment hash to the one matching our own choice
	h_decommitChoice := h_decommit0
	mask := -byte(r.choice)
	for i := 0; i < len(r.receivedChallenge); i++ {
		h_decommitChoice[i] ^= (mask & (h_decommitChoice[i] ^ h_decommit1[i]))
	}
	if subtle.ConstantTimeCompare(h_decommitChoice, r.hh_randChoice) != 1 {
		return nil, fmt.Errorf("RandomOTReceive Round 3: incorrect decommitment")
	}

	return r.randChoice, nil
}

type RandomOTSender struct {
	// After setup
	hash *hash.Hash
	b    curve.Scalar
	_B   curve.Point
	// After round 1
	rand0 []byte
	rand1 []byte

	decommit0 []byte
	decommit1 []byte

	h_decommit0 []byte
}

func NewRandomOTSender(hash *hash.Hash, result *RandomOTSetupSendResult) *RandomOTSender {
	return &RandomOTSender{hash: hash, b: result.b, _B: result._B}
}

type RandomOTSendRound1Message struct {
	challenge []byte
}

func (r *RandomOTSender) Round1(msg *RandomOTReceiveRound1Message) *RandomOTSendRound1Message {
	// We can compute the two random pads:
	//    rand0 = H(b * A)
	//    rand1 = H(b * (A - B))
	r.rand0 = make([]byte, params.SecBytes)
	H := r.hash.Clone()
	_ = H.WriteAny(r.b.Act(msg._A))
	_, _ = H.Digest().Read(r.rand0)

	r.rand1 = make([]byte, params.SecBytes)
	H = r.hash.Clone()
	_ = H.WriteAny(r.b.Act(msg._A.Sub(r._B)))
	_, _ = H.Digest().Read(r.rand1)

	// Compute the challenge:
	//   H(H(rand0)) ^ H(H(rand1))
	r.decommit0 = make([]byte, params.SecBytes)
	H = hash.New()
	_ = H.WriteAny(r.rand0)
	_, _ = H.Digest().Read(r.decommit0)

	r.decommit1 = make([]byte, params.SecBytes)
	H = hash.New()
	_ = H.WriteAny(r.rand1)
	_, _ = H.Digest().Read(r.decommit1)

	r.h_decommit0 = make([]byte, params.SecBytes)
	H = hash.New()
	_ = H.WriteAny(r.decommit0)
	_, _ = H.Digest().Read(r.h_decommit0)

	challenge := make([]byte, params.SecBytes)
	H = hash.New()
	_ = H.WriteAny(r.decommit1)
	_, _ = H.Digest().Read(challenge)

	for i := 0; i < len(challenge) && i < len(r.h_decommit0); i++ {
		challenge[i] ^= r.h_decommit0[i]
	}

	return &RandomOTSendRound1Message{challenge: challenge}
}

type RandomOTSendRound2Message struct {
	decommit0 []byte
	decommit1 []byte
}

type RandomOTSendResult struct {
	rand0 []byte
	rand1 []byte
}

func (r *RandomOTSender) Round2(msg *RandomOTReceiveRound2Message) (*RandomOTSendRound2Message, *RandomOTSendResult, error) {
	if subtle.ConstantTimeCompare(msg.response, r.h_decommit0) != 1 {
		return nil, nil, fmt.Errorf("RandomOTSender Round2: invalid response")
	}

	return &RandomOTSendRound2Message{decommit0: r.decommit0, decommit1: r.decommit1}, &RandomOTSendResult{rand0: r.rand0, rand1: r.rand1}, nil
}
