package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/pedersen"
)

type (
	round0 struct {
		selfParty *partyState
		parties   map[party.ID]*partyState

		rho uint32

		paillierSecret *paillier.SecretKey
	}
)

type partyState struct {
	Y              curve.Point
	PaillierPublic *paillier.PublicKey
	Pedersen       *pedersen.Verifier
}
