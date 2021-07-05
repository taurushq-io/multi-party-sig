package refresh

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

const protocolID round.ProtocolID = 2

const (
	MessageTypeRefresh1 = (round.MessageID(protocolID) << 16) + iota
	MessageTypeRefresh2
	MessageTypeRefresh3
	MessageTypeRefresh4
	MessageTypeRefresh5
)

func (m *Message) Validate() error {
	h := m.GetHeader()
	if h == nil {
		return errors.New("refresh.Message: header is nil")
	}
	msgType := m.ID()
	switch msgType {
	case MessageTypeRefresh1:
		return m.GetRefresh1().Validate()
	case MessageTypeRefresh2:
		return m.GetRefresh2().Validate()
	case MessageTypeRefresh3:
		return m.GetRefresh3().Validate()
	case MessageTypeRefresh4:
		return m.GetRefresh4().Validate()
	case MessageTypeRefresh5:
		return m.GetRefresh5().Validate()
	default:
		return errors.New("refresh.Message: invalid content")
	}
}

func (m *Message) ID() round.MessageID {
	switch m.Content.(type) {
	case *Message_Refresh1:
		return MessageTypeRefresh1
	case *Message_Refresh2:
		return MessageTypeRefresh2
	case *Message_Refresh3:
		return MessageTypeRefresh3
	case *Message_Refresh4:
		return MessageTypeRefresh4
	case *Message_Refresh5:
		return MessageTypeRefresh5
	default:
		return round.MessageIDInvalid
	}
}

func NewMessageRefresh1(selfID party.ID, commitment []byte) []round.Message {
	return []round.Message{&Message{
		Header: &round.Header{
			From:      selfID,
			Broadcast: round.Broadcast_Reliable,
		},
		Content: &Message_Refresh1{
			Refresh1: &Refresh1{
				Commitment: commitment,
			},
		},
	}}
}

func (m *Refresh1) Validate() error {
	if m == nil {
		return errors.New("refresh.round1: message is nil")
	}
	if l := len(m.Commitment); l != params.HashBytes {
		return fmt.Errorf("refresh.round1: invalid commitment length (got %d, expected %d)", l, params.HashBytes)
	}
	return nil
}

func NewMessageRefresh2(selfID party.ID, echoHash []byte) []round.Message {
	return []round.Message{&Message{
		Header: &round.Header{
			From:      selfID,
			Broadcast: round.Broadcast_Basic,
		},
		Content: &Message_Refresh2{
			Refresh2: &Refresh2{
				HashEcho: echoHash,
			},
		},
	}}
}

func (m *Refresh2) Validate() error {
	if m == nil {
		return errors.New("refresh.round2: message is nil")
	}
	if l := len(m.HashEcho); l != params.HashBytes {
		return fmt.Errorf("refresh.round2: invalid echo hash length (got %d, expected %d)", l, params.HashBytes)
	}
	return nil
}

func NewMessageRefresh3(selfID party.ID, msg *Refresh3) []round.Message {
	return []round.Message{&Message{
		Header: &round.Header{
			From:      selfID,
			Broadcast: round.Broadcast_Basic,
		},
		Content: &Message_Refresh3{
			Refresh3: msg,
		},
	}}
}

func (m *Refresh3) Validate() error {
	if m == nil {
		return errors.New("refresh.round3: message is nil")
	}
	if lRho := len(m.Rho); lRho != params.SecBytes {
		return fmt.Errorf("refresh.round3: invalid Rho length (got %d, expected %d)", lRho, params.SecBytes)
	}

	if lU := len(m.Rho); lU != params.SecBytes {
		return fmt.Errorf("refresh.round3: invalid Decommitment length (got %d, expected %d)", lU, params.SecBytes)
	}

	if err := m.Pedersen.Validate(); err != nil {
		return fmt.Errorf("refresh.round3: %w", err)
	}

	if m.VSSPolynomial == nil {
		return errors.New("refresh.round3: VSSPolynomial is nil")
	}

	return nil
}

func NewMessageRefresh4(selfID, to party.ID, msg *Refresh4) round.Message {
	return &Message{
		Header: &round.Header{
			From:      selfID,
			To:        to,
			Broadcast: round.Broadcast_None,
		},
		Content: &Message_Refresh4{
			Refresh4: msg,
		},
	}
}

func (m *Refresh4) Validate() error {
	if m == nil {
		return errors.New("refresh.round4: message is nil")
	}
	if m.Mod == nil {
		return errors.New("refresh.round4: zkmod proof is nil")
	}
	if m.Prm == nil {
		return errors.New("refresh.round4: zkprm proof is nil")
	}
	if m.Share == nil {
		return errors.New("refresh.round4: Share proof is nil")
	}
	return nil
}

func NewMessageRefresh5(selfID party.ID, proof *curve.Scalar) []round.Message {
	return []round.Message{&Message{
		Header: &round.Header{
			From:      selfID,
			Broadcast: round.Broadcast_Basic,
		},
		Content: &Message_Refresh5{
			Refresh5: &Refresh5{Proof: proof},
		},
	}}
}

func (m *Refresh5) Validate() error {
	if m == nil {
		return errors.New("refresh.round5: message is nil")
	}
	if m.Proof == nil {
		return errors.New("refresh.round5: sch proof is nil")
	}
	return nil
}
