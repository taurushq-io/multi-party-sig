package ot

import (
	"bytes"
	"testing"
	"testing/quick"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

var group = curve.Secp256k1{}

func runRandomOT(choice bool, hash *hash.Hash) (*RandomOTSendResult, []byte, error) {
	safeChoice := safenum.Choice(0)
	if choice {
		safeChoice = 1
	}
	msgS0, setupS := RandomOTSetupSend(hash.Clone(), group)
	setupR, err := RandomOTSetupReceive(hash.Clone(), msgS0)
	if err != nil {
		return nil, nil, err
	}
	receiver := NewRandomOTReceiver(hash.Clone(), safeChoice, setupR)
	sender := NewRandomOTSender(hash.Clone(), setupS)

	msgR1 := receiver.Round1()
	msgS1 := sender.Round1(msgR1)
	msgR2 := receiver.Round2(msgS1)
	msgS2, resultS, err := sender.Round2(msgR2)
	if err != nil {
		return nil, nil, err
	}
	resultR, err := receiver.Round3(msgS2)
	if err != nil {
		return nil, nil, err
	}
	return resultS, resultR, err
}

func testRandomOT(choice bool, init []byte) bool {
	hash := hash.New()
	_ = hash.WriteAny(init)
	result, randChoice, err := runRandomOT(choice, hash)
	if err != nil {
		return false
	}
	// This should happen only with negligeable probability
	if bytes.Equal(result.rand0, result.rand1) {
		return false
	}
	if choice {
		return bytes.Equal(result.rand1, randChoice)
	} else {
		return bytes.Equal(result.rand0, randChoice)
	}
}

func TestRandomOT(t *testing.T) {
	err := quick.Check(testRandomOT, &quick.Config{})
	if err != nil {
		t.Error(err)
	}
}
