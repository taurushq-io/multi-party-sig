package sign

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
)

func NewRound(session *session.Session, selfID party.ID, secret *session.Secret, message []byte /*, parameters *Parameters*/) (*round1, error) {
	//if parameters == nil {
	//	parameters = &Parameters{}
	//}
	//parameters.fill(session.Parties())
	//if !parameters.verify(session.N()) {
	//	return nil, errors.New("parameters were not correctly generated")
	//}

	err := session.Validate(secret)
	if err != nil {
		return nil, fmt.Errorf("newRound: config: %w", err)
	}

	parties := make(map[party.ID]*localParty, session.N())
	public := session.Public()
	for _, j := range session.Parties() {
		parties[j] = newParty(j, public[j])
	}

	base, err := round.NewBaseRound(session, selfID)
	if err != nil {
		return nil, err
	}

	return &round1{
		BaseRound: base,
		paillier:  secret.Paillier(),
		ecdsa:     secret.ShareECDSA(),
		//p:         parameters,
		thisParty: parties[selfID],
		parties:   parties,
		message:   message,
	}, nil
}
