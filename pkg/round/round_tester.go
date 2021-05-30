package round

import "github.com/taurusgroup/cmp-ecdsa/pkg/party"

type LocalProtocol struct {
	PartySecret *party.Secret
	R           Round
}

func (p LocalProtocol) ID() party.ID {
	return p.R.(*BaseRound).SelfID
}
