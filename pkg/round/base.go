package round

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
)

type BaseRound struct {
	S *session.Session
	H *hash.Hash

	SelfID    party.ID
	SelfIndex int
}

func NewBaseRound(session *session.Session, selfID party.ID) (*BaseRound, error) {
	h, err := session.Hash()
	if err != nil {
		return nil, fmt.Errorf("newRound: session.Hash: %w", err)
	}
	return &BaseRound{
		S:         session,
		H:         h,
		SelfID:    selfID,
		SelfIndex: session.Parties().GetIndex(selfID),
	}, nil
}
