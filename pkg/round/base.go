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

	Secret *party.Secret

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

func NewBaseRound(session *Session, secret *party.Secret) (*BaseRound, error) {
	if err := session.Validate(secret); err != nil {
		return nil, err
	}

	h, err := session.Hash()
	if err != nil {
		return nil, fmt.Errorf("newRound: session.Hash: %w", err)
	}

	return &BaseRound{
		S:         session,
		H:         h,
		Secret:    secret,
		SelfID:    secret.ID,
		SelfIndex: session.Parties().GetIndex(secret.ID),
	}, nil
}
