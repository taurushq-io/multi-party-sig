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

func (b BaseRound) ProcessMessage(msg *pb.Message) error {
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

func NewBaseRound(session *Session) (*BaseRound, error) {
	s2 := session.Clone()
	if err := s2.Validate(); err != nil {
		return nil, err
	}

	h, err := s2.Hash()
	if err != nil {
		return nil, fmt.Errorf("newRound: session.Hash: %w", err)
	}

	return &BaseRound{
		S:         s2,
		H:         h,
		SelfID:    s2.SelfID(),
		SelfIndex: s2.Parties.GetIndex(s2.SelfID()),
	}, nil
}
