package sign

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

const protocolID round.MessageProtocol = 3

const (
	MessageTypeSign1 = (round.MessageType(protocolID) << 16) + iota
	MessageTypeSign2
	MessageTypeSign3
	MessageTypeSign4
)

func (m *Message) Validate() error {
	h := m.GetHeader()
	if h == nil {
		return errors.New("sign.Message: header is nil")
	}
	msgType := m.Type()
	switch msgType {
	case MessageTypeSign1:
		return m.GetSign1().Validate()
	case MessageTypeSign2:
		return m.GetSign2().Validate()
	case MessageTypeSign3:
		return m.GetSign3().Validate()
	case MessageTypeSign4:
		return m.GetSign4().Validate()
	default:
		return errors.New("sign.Message: invalid content")
	}
}

func (m *Message) Type() round.MessageType {
	switch m.Content.(type) {
	case *Message_Sign1:
		return MessageTypeSign1
	case *Message_Sign2:
		return MessageTypeSign2
	case *Message_Sign3:
		return MessageTypeSign3
	case *Message_Sign4:
		return MessageTypeSign4
	default:
		return round.MessageTypeInvalid
	}
}

func NewMessageSign1(selfID, to party.ID, msg *Sign1) round.Message {
	return &Message{
		Header: &round.Header{
			From:      selfID,
			To:        to,
			Broadcast: round.Broadcast_None,
		},
		Content: &Message_Sign1{
			Sign1: msg,
		}}

}

func (m *Sign1) Validate() error {
	if m == nil {
		return errors.New("sign.round1: message is nil")
	}
	if m.G == nil || m.K == nil {
		return errors.New("sign.round1: K or G is nil")
	}
	return nil
}

func NewMessageSign2(selfID, to party.ID, msg *Sign2) round.Message {
	return &Message{
		Header: &round.Header{
			From:      selfID,
			To:        to,
			Broadcast: round.Broadcast_None,
		},
		Content: &Message_Sign2{
			Sign2: msg,
		},
	}
}

func (m *MtAMessage) Validate() error {
	if m.D == nil || m.F == nil || m.Proof == nil {
		return errors.New("sign.mta: message contains nil fields")
	}
	return nil
}

func (m *Sign2) Validate() error {
	if m == nil {
		return errors.New("sign.round2: message is nil")
	}
	if m.BigGammaShare == nil || m.DeltaMtA == nil || m.ChiMtA == nil || m.ProofLog == nil {
		return errors.New("sign.round2: message contains nil fields")
	}
	if err := m.DeltaMtA.Validate(); err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if err := m.ChiMtA.Validate(); err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	return nil
}

func NewMessageSign3(selfID, to party.ID, msg *Sign3) round.Message {
	return &Message{
		Header: &round.Header{
			From:      selfID,
			To:        to,
			Broadcast: round.Broadcast_None,
		},
		Content: &Message_Sign3{
			Sign3: msg,
		},
	}
}

func (m *Sign3) Validate() error {
	if m == nil {
		return errors.New("sign.round3: message is nil")
	}
	if m.DeltaShare == nil || m.BigDeltaShare == nil || m.ProofLog == nil {
		return errors.New("sign.round3: message contains nil fields")
	}

	return nil
}

func NewMessageSign4(selfID party.ID, msg *Sign4) []round.Message {
	return []round.Message{&Message{
		Header: &round.Header{
			From:      selfID,
			Broadcast: round.Broadcast_Basic,
		},
		Content: &Message_Sign4{
			Sign4: msg,
		},
	}}
}

func (m *Sign4) Validate() error {
	if m == nil {
		return errors.New("sign.round4: message is nil")
	}
	if m.SigmaShare == nil {
		return errors.New("sign.round4: message contains nil fields")
	}
	return nil
}
