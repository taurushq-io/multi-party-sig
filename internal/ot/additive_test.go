package ot

import (
	"crypto/rand"
	"testing"

	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

func runAdditiveOT(hash *hash.Hash, choices []byte, alpha [2]curve.Scalar, sendSetup *CorreOTSendSetup, receiveSetup *CorreOTReceiveSetup) (AdditiveOTSendResult, AdditiveOTReceiveResult, error) {
	sender := NewAdditiveOTSender(hash.Clone(), sendSetup, 8*len(choices), alpha)
	receiver := NewAdditiveOTReceiver(hash.Clone(), receiveSetup, alpha[0].Curve(), choices)
	msgR1 := receiver.Round1()
	msgS1, sendResult, err := sender.Round1(msgR1)
	if err != nil {
		return nil, nil, err
	}
	receiveResult, err := receiver.Round2(msgS1)
	if err != nil {
		return nil, nil, err
	}
	return sendResult, receiveResult, nil
}

func TestAdditiveOT(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	sendSetup, receiveSetup, err := runCorreOTSetup(pl, hash.New())
	if err != nil {
		t.Error(err)
	}

	H := hash.New()
	for i := 0; i < 10; i++ {
		_ = H.WriteAny([]byte{byte(i)})
		choices := make([]byte, 11)
		_, _ = rand.Read(choices)
		var alpha [2]curve.Scalar
		alpha[0] = sample.Scalar(rand.Reader, testGroup)
		alpha[1] = sample.Scalar(rand.Reader, testGroup)
		sendResult, receiveResult, err := runAdditiveOT(H, choices, alpha, sendSetup, receiveSetup)
		if err != nil {
			t.Error(err)
		}
		var expected [2]curve.Scalar
		expected[0] = testGroup.NewScalar()
		expected[1] = testGroup.NewScalar()

		for i := 0; i < 8*len(choices); i++ {
			choice := bitAt(i, choices) == 1
			expected[0].Set(sendResult[i][0]).Negate()
			expected[1].Set(sendResult[i][1]).Negate()
			if choice {
				expected[0].Add(alpha[0])
				expected[1].Add(alpha[1])
			}
			if !(expected[0].Equal(receiveResult[i][0]) && expected[1].Equal(receiveResult[i][1])) {
				t.Error("incorrect additive OT")
			}
		}
	}
}

func BenchmarkAdditiveOT(b *testing.B) {
	b.StopTimer()
	pl := pool.NewPool(0)
	defer pl.TearDown()
	var alpha [2]curve.Scalar
	alpha[0] = sample.Scalar(rand.Reader, testGroup)
	alpha[1] = sample.Scalar(rand.Reader, testGroup)
	sendSetup, receiveSetup, _ := runCorreOTSetup(pl, hash.New())
	choices := make([]byte, 2*testGroup.ScalarBits()+2*params.StatParam)
	_, _ = rand.Read(choices)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		runAdditiveOT(hash.New(), choices, alpha, sendSetup, receiveSetup)
	}
}
