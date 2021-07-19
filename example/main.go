package main

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/protocols/refresh"
	sign2 "github.com/taurusgroup/cmp-ecdsa/protocols/sign"
)

type Network interface {
	Send(msg *round.Message)
	Next(id party.ID) <-chan *round.Message
}

type chanNetwork struct {
	parties        party.IDSlice
	listenChannels map[party.ID]chan *round.Message
}

func newNetwork(parties party.IDSlice) Network {
	n := len(parties)
	lc := make(map[party.ID]chan *round.Message, n)
	for _, id := range parties {
		lc[id] = make(chan *round.Message, 2*n)
	}
	return &chanNetwork{
		parties:        parties,
		listenChannels: lc,
	}
}

func (c *chanNetwork) Next(id party.ID) <-chan *round.Message {
	return c.listenChannels[id]
}

func (c *chanNetwork) Send(msg *round.Message) {
	if len(msg.To) == 0 {
		for _, id := range c.parties {
			if id == msg.From {
				continue
			}
			c.listenChannels[id] <- msg
		}
	} else {
		for _, id := range msg.To {
			c.listenChannels[id] <- msg
		}
	}
}

func handlerLoop(id party.ID, h *protocol.Handler, n Network) error {
	for {
		select {
		case <-h.Done():
			fmt.Println("done")
			return nil
		case msg := <-h.Listen():
			// Get new message to send
			if msg == nil {
				fmt.Println("Got nil")
				continue
			}
			go n.Send(msg)
		case msg := <-n.Next(id):
			// process new message
			if msg == nil {
				continue
			}
			err := h.Update(msg)
			if err != nil {
				return err
			}
		}
	}
}

func Do(id party.ID, ids party.IDSlice, threshold int, message []byte, n Network, wg *sync.WaitGroup) error {
	defer wg.Done()
	// KEYGEN
	hKeygen, err := protocol.NewHandler(keygen.StartKeygen(ids, 2, id))
	if err != nil {
		return err
	}
	log.Println(id, "starting keygen")
	err = handlerLoop(id, hKeygen, n)
	if err != nil {
		return err
	}

	log.Println(id, "finished keygen")
	keygenResult, err := hKeygen.Result()
	if err != nil {
		return err
	}

	keygenSession := keygenResult.(*refresh.Result).Session
	keygenSecret := keygenResult.(*refresh.Result).Secret

	// REFRESH
	hRefresh, err := protocol.NewHandler(keygen.StartRefresh(keygenSession, keygenSecret))
	if err != nil {
		return err
	}
	log.Println(id, "starting refresh")
	err = handlerLoop(id, hRefresh, n)
	if err != nil {
		return err
	}
	log.Println(id, "finished refresh")

	refreshResult, err := hRefresh.Result()
	if err != nil {
		return err
	}

	refreshSession := refreshResult.(*refresh.Result).Session
	refreshSecret := refreshResult.(*refresh.Result).Secret

	// SIGN
	signers := ids[:threshold+1]
	if !signers.Contains(id) {
		return nil
	}

	hSign, err := protocol.NewHandler(sign2.StartSign(refreshSession, refreshSecret, signers, message))
	if err != nil {
		return err
	}
	log.Println(id, "starting sign")
	err = handlerLoop(id, hSign, n)
	if err != nil {
		return err
	}
	log.Println(id, "finished sign")

	signResult, err := hSign.Result()
	if err != nil {
		return err
	}
	signature := signResult.(*sign2.Result).Signature
	r, s := signature.ToRS()
	if !ecdsa.Verify(refreshSession.PublicKey(), message, r, s) {
		return errors.New("signature failed to verify")
	}
	return nil
}

func main() {
	ids := party.IDSlice{"a", "b", "c"}
	//ids := party.IDSlice{"a", "b", "c", "d", "e"}
	threshold := 2
	message_to_sign := []byte("hello")

	net := newNetwork(ids)

	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id party.ID) {
			if err := Do(id, ids, threshold, message_to_sign, net, &wg); err != nil {
				fmt.Println(err)
			}
		}(id)
	}
	wg.Wait()
}
