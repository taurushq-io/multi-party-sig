package main

import (
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

type Network interface {
	Send(msg *protocol.Message)
	Next(id party.ID) <-chan *protocol.Message
}

type chanNetwork struct {
	parties        party.IDSlice
	listenChannels map[party.ID]chan *protocol.Message
}

func NewNetwork(parties party.IDSlice) Network {
	n := len(parties)
	lc := make(map[party.ID]chan *protocol.Message, n)
	for _, id := range parties {
		lc[id] = make(chan *protocol.Message, 2*n)
	}
	return &chanNetwork{
		parties:        parties,
		listenChannels: lc,
	}
}

func (c *chanNetwork) Next(id party.ID) <-chan *protocol.Message {
	return c.listenChannels[id]
}

func (c *chanNetwork) Send(msg *protocol.Message) {
	if msg.Broadcast() {
		for _, id := range c.parties {
			c.listenChannels[id] <- msg
		}
	} else {
		c.listenChannels[msg.To] <- msg
	}
}
