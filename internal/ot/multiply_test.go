package ot

import (
	"crypto/rand"
	"testing"

	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

func runMultiply(hash *hash.Hash, sendSetup *CorreOTSendSetup, receiveSetup *CorreOTReceiveSetup, alpha, beta curve.Scalar) (curve.Scalar, curve.Scalar, error) {
	sender := NewMultiplySender(hash.Clone(), sendSetup, alpha)
	receiver, err := NewMultiplyReceiver(hash.Clone(), receiveSetup, beta)
	if err != nil {
		return nil, nil, err
	}
	msgR1 := receiver.Round1()
	msgS1, shareA, err := sender.Round1(msgR1)
	if err != nil {
		return nil, nil, err
	}
	shareB, err := receiver.Round2(msgS1)
	return shareA, shareB, err
}

func TestMultiply(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	sendSetup, receiveSetup, err := runCorreOTSetup(pl, hash.New())
	if err != nil {
		t.Error(err)
	}

	H := hash.New()
	for i := 0; i < 1; i++ {
		_ = H.WriteAny([]byte{byte(i)})
		alpha := sample.Scalar(rand.Reader, testGroup)
		beta := sample.Scalar(rand.Reader, testGroup)
		a, b, err := runMultiply(H, sendSetup, receiveSetup, alpha, beta)
		if err != nil {
			t.Error(err)
		}
		alphabeta := testGroup.NewScalar().Set(alpha).Mul(beta)
		ab := testGroup.NewScalar().Set(a).Add(b)
		if !alphabeta.Equal(ab) {
			t.Error("multiply failed to produce valid shares")
		}
	}
}

func BenchmarkMultiply(b *testing.B) {
	b.StopTimer()
	pl := pool.NewPool(0)
	defer pl.TearDown()
	sendSetup, receiveSetup, _ := runCorreOTSetup(pl, hash.New())
	alpha := sample.Scalar(rand.Reader, testGroup)
	beta := sample.Scalar(rand.Reader, testGroup)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		runMultiply(hash.New(), sendSetup, receiveSetup, alpha, beta)
	}
}
