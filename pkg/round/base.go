package round

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

type BaseRound struct {
	S *Session
	H *hash.Hash

	SelfID    party.ID
	SelfIndex int
}

func NewBaseRound(session *Session) (*BaseRound, error) {
	if err := session.Validate(); err != nil {
		return nil, err
	}

	h, err := session.Hash()
	if err != nil {
		return nil, fmt.Errorf("round.NewBaseRound: %w", err)
	}

	return &BaseRound{
		S:         session,
		H:         h,
		SelfID:    session.SelfID(),
		SelfIndex: session.PartyIDs.GetIndex(session.SelfID()),
	}, nil
}

func (b BaseRound) ProcessMessage(*pb.Message) error {
	return nil
}

func (b BaseRound) GenerateMessages() ([]*pb.Message, error) {
	return nil, nil
}

func (b BaseRound) Finalize() (Round, error) {
	return nil, nil
}

func (b BaseRound) MessageType() pb.MessageType {
	return pb.MessageType_TypeInvalid
}
