package party

import (
	"encoding/json"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

var _ json.Marshaler = (*Public)(nil)
var _ json.Unmarshaler = (*Public)(nil)

type jsonParty struct {
	ID    ID           `json:"id"`
	ECDSA *curve.Point `json:"ecdsa"`
	N     []byte       `json:"n"`
	S     []byte       `json:"s"`
	T     []byte       `json:"t"`
}

func (p Public) MarshalJSON() ([]byte, error) {
	x := jsonParty{
		ID:    p.ID,
		ECDSA: p.ECDSA,
		N:     p.Pedersen.N.Bytes(),
		S:     p.Pedersen.S.Bytes(),
		T:     p.Pedersen.T.Bytes(),
	}
	return json.Marshal(x)
}

func (p *Public) UnmarshalJSON(bytes []byte) error {
	var x jsonParty
	err := json.Unmarshal(bytes, &x)
	if err != nil {
		return err
	}
	var n, s, t big.Int
	n.SetBytes(x.N)
	s.SetBytes(x.S)
	t.SetBytes(x.T)
	p.ID = x.ID
	p.ECDSA = x.ECDSA
	p.Paillier = paillier.NewPublicKey(&n)
	p.Pedersen = &pedersen.Parameters{
		N: &n,
		S: &s,
		T: &t,
	}
	return p.Validate()
}
