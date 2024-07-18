package ot

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

func runExtendedOT(hash *hash.Hash, choices []byte, sendSetup *CorreOTSendSetup, receiveSetup *CorreOTReceiveSetup) (*ExtendedOTSendResult, *ExtendedOTReceiveResult, error) {
	msg, receiveResult := ExtendedOTReceive(hash.Clone(), receiveSetup, choices)
	sendResult, err := ExtendedOTSend(hash.Clone(), sendSetup, 8*len(choices), msg)
	if err != nil {
		return nil, nil, err
	}
	return sendResult, receiveResult, nil
}

func TestExtendedOT(t *testing.T) {
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
		sendResult, receiveResult, err := runExtendedOT(H, choices, sendSetup, receiveSetup)
		if err != nil {
			t.Error(err)
		}
		for i := 0; i < 8*len(choices); i++ {
			choice := bitAt(i, choices) == 1
			expected := make([]byte, params.OTBytes)
			if choice {
				copy(expected, sendResult._V1[i][:])
			} else {
				copy(expected, sendResult._V0[i][:])
			}
			if !bytes.Equal(receiveResult._VChoices[i][:], expected) {
				t.Error("incorrect Extended OT")
			}

		}
	}
}

func BenchmarkExtendedOT(b *testing.B) {
	b.StopTimer()
	pl := pool.NewPool(0)
	defer pl.TearDown()
	sendSetup, receiveSetup, _ := runCorreOTSetup(pl, hash.New())
	choices := make([]byte, params.OTBytes)
	_, _ = rand.Read(choices)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		runExtendedOT(hash.New(), choices, sendSetup, receiveSetup)
	}
}
