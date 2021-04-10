package refresh

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/wip/interfaces"
)

// Party is the state we store for a remote party.
// The messages are embedded to make access to the attributes easier.
type Party struct {
	interfaces.Peer
	PaillierPublic *paillier.PublicKey

	*message1
	*message2
	*message3
}

func (p *Party) StoreMessage(msg message.Message) error {
	msgContent := msg.G()
	switch msgContent.(type) {
	case message1:
		if p.message1 != nil {
			return errors.New("already received message1")
		}
		p.message1 = msgContent.(*message1)
	case message2:
		if p.message2 != nil {
			return errors.New("already received message2")
		}
		p.message2 = msgContent.(*message2)
	case message3:
		if p.message3 != nil {
			return errors.New("already received message3")
		}
		p.message3 = msgContent.(*message3)
	default:
		return errors.New("wrong message type")
	}

}

// TODO Methods for unmarshalling ProtoBufs the party
