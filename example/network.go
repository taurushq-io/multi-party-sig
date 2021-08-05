package example

import (
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/message"
)

type Network interface {
	Send(msg *message.Message)
	Next(id party.ID) <-chan *message.Message
}

type chanNetwork struct {
	parties        party.IDSlice
	listenChannels map[party.ID]chan *message.Message
}

func NewNetwork(parties party.IDSlice) Network {
	n := len(parties)
	lc := make(map[party.ID]chan *message.Message, n)
	for _, id := range parties {
		lc[id] = make(chan *message.Message, 2*n)
	}
	return &chanNetwork{
		parties:        parties,
		listenChannels: lc,
	}
}

func (c *chanNetwork) Next(id party.ID) <-chan *message.Message {
	return c.listenChannels[id]
}

func (c *chanNetwork) Send(msg *message.Message) {
	if msg.Broadcast() {
		for _, id := range c.parties {
			c.listenChannels[id] <- msg
		}
	} else {
		for _, id := range msg.To {
			c.listenChannels[id] <- msg
		}
	}
}
