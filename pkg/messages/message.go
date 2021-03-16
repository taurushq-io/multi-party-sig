package messages

import "github.com/taurusgroup/cmp-ecdsa/pkg/party"

type Type uint8

const (
	SizeMessageType = 1
	SizeHeader      = SizeMessageType + 2*party.ByteSize
)

type Message struct {
	typeID   Type
	from, to party.ID
	content  []byte
}

func FromBytes(in []byte) *Message {
	_ = in[SizeHeader]
	typeID := Type(in[0])
	from := party.FromBytes(in[SizeMessageType:])
	to := party.FromBytes(in[SizeMessageType+party.ByteSize:])
	content := make([]byte, len(in)-SizeHeader)
	copy(content, in[SizeHeader:])
	return &Message{
		typeID:  typeID,
		from:    from,
		to:      to,
		content: content,
	}
}

func (m *Message) Content() []byte {
	return m.content
}

func (m *Message) From() party.ID {
	return m.from
}

func (m *Message) To() party.ID {
	return m.to
}

func (m *Message) IsBroadcast() bool {
	return m.to == 0
}

func (m *Message) Type() Type {
	return m.typeID
}
