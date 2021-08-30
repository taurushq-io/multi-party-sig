package test

import (
	"errors"
	"log"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

func HandlerLoop(id party.ID, h *protocol.Handler, network *Network) error {
	log.Println(h, "start")
	for {
		select {

		// outgoing messages
		case msg, ok := <-h.Listen():
			if !ok {
				log.Println(h, "done")
				var pErr protocol.Error
				_, err := h.Result()
				if errors.As(err, &pErr) {
					log.Println(h, "error", pErr)
				}
				<-network.Done(id)
				// the channel was closed, indicating that the protocol is done executing.
				return nil
			}
			go network.Send(msg)

		// incoming messages
		case msg := <-network.Next(id):
			h.Update(msg)
		}
	}
}
