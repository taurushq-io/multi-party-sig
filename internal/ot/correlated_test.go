package ot

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

func runCorreOTSetup(pl *pool.Pool, hash *hash.Hash) (*CorreOTSendSetup, *CorreOTReceiveSetup, error) {
	sender := NewCorreOTSetupSender(pl, hash.Clone())
	receiver := NewCorreOTSetupReceiver(pl, hash.Clone(), testGroup)
	msgR1 := receiver.Round1()
	msgS1, err := sender.Round1(msgR1)
	if err != nil {
		fmt.Println(err)
		return nil, nil, err
	}
	msgR2, err := receiver.Round2(msgS1)
	if err != nil {
		return nil, nil, err
	}
	msgS2 := sender.Round2(msgR2)
	msgR3, receiveSetup, err := receiver.Round3(msgS2)
	if err != nil {
		fmt.Println(err)
		return nil, nil, err
	}
	sendSetup, err := sender.Round3(msgR3)
	if err != nil {
		fmt.Println(err)
		return nil, nil, err
	}
	return sendSetup, receiveSetup, nil
}

func TestCorreOTSetup(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	for i := 0; i < 10; i++ {
		sendSetup, receiveSetup, err := runCorreOTSetup(pl, hash.New())
		if err != nil {
			t.Error(err)
		}
		for i := 0; i < params.OTParam; i++ {
			// This should only fail with negligeable probability normally
			if bytes.Equal(receiveSetup._K_0[i][:], receiveSetup._K_1[i][:]) {
				t.Error("K_0[i] == K_1[i]")
			}
			choice := bitAt(i, sendSetup._Delta[:]) == 1
			array := receiveSetup._K_0[i][:]
			if choice {
				array = receiveSetup._K_1[i][:]
			}
			if !bytes.Equal(sendSetup._K_Delta[i][:], array) {
				t.Error("K_Delta doesn't match")
			}
		}
	}
}

func runCorreOT(hash *hash.Hash, choices []byte, sendSetup *CorreOTSendSetup, receiveSetup *CorreOTReceiveSetup) (*CorreOTSendResult, *CorreOTReceiveResult, error) {
	msgR1, receiveResult := CorreOTReceive(hash.Clone(), receiveSetup, choices)
	sendResult, err := CorreOTSend(hash.Clone(), sendSetup, 8*len(choices), msgR1)
	if err != nil {
		return nil, nil, err
	}
	return sendResult, receiveResult, nil
}

func TestCorreOT(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	sendSetup, receiveSetup, err := runCorreOTSetup(pl, hash.New())
	if err != nil {
		t.Error(err)
	}
	H := hash.New()
	for i := 0; i < 10; i++ {
		_ = H.WriteAny([]byte{byte(i)})
		choices := make([]byte, params.OTBytes)
		_, _ = rand.Read(choices)
		sendResult, receiveResult, err := runCorreOT(H, choices, sendSetup, receiveSetup)
		if err != nil {
			t.Error(err)
		}
		for i := 0; i < params.OTParam; i++ {
			choice := bitAt(i, choices) == 1
			expected := make([]byte, params.OTBytes)
			copy(expected, receiveResult._T[i][:])
			if choice {
				for j := 0; j < params.OTBytes; j++ {
					expected[j] ^= sendSetup._Delta[j]
				}
			}
			actual := sendResult._Q[i][:]
			if !bytes.Equal(actual, expected) {
				t.Error("incorrect Correlated OT")
			}
		}
	}
}

func BenchmarkCorreOTSetup(b *testing.B) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	for i := 0; i < b.N; i++ {
		runCorreOTSetup(pl, hash.New())
	}
}

func BenchmarkCorreOT(b *testing.B) {
	b.StopTimer()
	pl := pool.NewPool(0)
	defer pl.TearDown()
	sendSetup, receiveSetup, _ := runCorreOTSetup(pl, hash.New())
	choices := make([]byte, params.OTBytes)
	_, _ = rand.Read(choices)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		runCorreOT(hash.New(), choices, sendSetup, receiveSetup)
	}
}
