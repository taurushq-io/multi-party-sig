package round

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
)

// BaseRound can be inherited by any first round of a protocol.
type BaseRound struct {
	S    session.Session
	Hash *hash.Hash

	SelfID    party.ID
	SelfIndex int

	name   string
	number int
}

type CreateFunc func(s session.Session) (Round, error)

func NewBaseRound(session session.Session, name string) (*BaseRound, error) {
	if err := session.Validate(); err != nil {
		return nil, err
	}

	return &BaseRound{
		S:         session,
		Hash:      session.Hash(),
		SelfID:    session.SelfID(),
		SelfIndex: session.PartyIDs().GetIndex(session.SelfID()),
		name:      name,
	}, nil
}

func (b BaseRound) ProcessMessage(Message) error {
	return nil
}

func (b BaseRound) GenerateMessages() ([]Message, error) {
	return nil, nil
}

func (b BaseRound) Finalize() (Round, error) {
	return nil, nil
}

func (b BaseRound) ExpectedMessageID() MessageID {
	return MessageIDInvalid
}

func (b BaseRound) ProtocolName() string {
	return b.name
}

func (b BaseRound) ProtocolID() ProtocolID {
	return 0
}

func (b BaseRound) Number() int {
	return b.number
}

func (b *BaseRound) Next() {
	b.number++
}
