package test

import (
	"errors"
	"log"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

// HandlerLoop blocks until the handler has finished. The result of the execution is given by Handler.Result().
func HandlerLoop(id party.ID, h protocol.Handler, network *Network) {
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
				return
			}
			go network.Send(msg)

		// incoming messages
		case msg := <-network.Next(id):
			h.Accept(msg)
		}
	}
}
