package interfaces

type Type uint8

const (
	SizeMessageType = 1
	SizeHeader      = SizeMessageType + 2*SizeID
)

type Message struct {
	typeID   Type
	from, to ID
	content  []byte
}

func FromBytes2(in []byte) *Message {
	return &Message{
		typeID:  Type(in[0]),
		from:    FromBytes(in[SizeMessageType:]),
		to:      FromBytes(in[SizeMessageType+SizeID:]),
		content: in,
	}
}

func (m *Message) Content() []byte {
	return m.content[SizeHeader:]
}

func (m *Message) ContentWithHeader() []byte {
	return m.content
}

func (m *Message) From() ID {
	return m.from
}

func (m *Message) To() ID {
	return m.to
}
