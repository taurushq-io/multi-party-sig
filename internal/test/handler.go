package test

import (
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

func HandlerLoop(id party.ID, h *protocol.Handler, network *Network) error {
	for {
		select {

		// outgoing messages
		case msg, ok := <-h.Listen():
			if msg == nil || !ok {
				h.Log.Info().Msg("done")
				<-network.Done(id)
				// the channel was closed, indicating that the protocol is done executing.
				return nil
			}
			go network.Send(msg)

		// incoming messages
		case msg := <-network.Next(id):
			err := h.Update(msg)

			if err != nil {
				h.Log.Warn().Err(err).Msg("skipping message")
			}
		}
	}
}
