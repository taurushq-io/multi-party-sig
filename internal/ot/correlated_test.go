package ot

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
)

func runCorreOTSetup(hash *hash.Hash) (*CorreOTSendSetup, *CorreOTReceiveSetup, error) {
	sender := NewCorreOTSetupSender(hash.Clone())
	receiver := NewCorreOTSetupReceive(hash.Clone(), testGroup)
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
	for i := 0; i < 1; i++ {
		sendSetup, receiveSetup, err := runCorreOTSetup(hash.New())
		if err != nil {
			t.Error(err)
		}
		for i := 0; i < params.SecParam; i++ {
			// This should only fail with negligeable probability normally
			if bytes.Equal(receiveSetup._K_0[i][:], receiveSetup._K_1[i][:]) {
				t.Error("K_0[i] == K_1[i]")
			}
			choice := ((sendSetup._Delta[i>>3] >> (i & 0b111)) & 1) == 1
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

func BenchmarkCorreOTSetup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		runCorreOTSetup(hash.New())
	}
}
