package round

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
)

type BaseRound struct {
	S    session.Session
	Hash *hash.Hash

	SelfID    party.ID
	SelfIndex int
}

func NewBaseRound(session session.Session) (*BaseRound, error) {
	if err := session.Validate(); err != nil {
		return nil, err
	}

	return &BaseRound{
		S:         session,
		Hash:      session.Hash(),
		SelfID:    session.SelfID(),
		SelfIndex: session.PartyIDs().GetIndex(session.SelfID()),
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

func (b BaseRound) MessageType() MessageType {
	return MessageTypeInvalid
}
