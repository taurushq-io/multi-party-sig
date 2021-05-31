package party

import (
	"encoding/hex"
	"encoding/json"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

var _ json.Marshaler = (*Public)(nil)
var _ json.Unmarshaler = (*Public)(nil)

type jsonParty struct {
	ID    ID     `json:"id"`
	SSID  string `json:"ssid"`
	ECDSA string `json:"ecdsa"`
	pedersen.Parameters
}

func (p Public) MarshalJSON() ([]byte, error) {
	ssidHex := hex.EncodeToString(p.SSID)
	ecdsaHex := hex.EncodeToString(p.ECDSA.BytesCompressed())
	x := jsonParty{
		ID:         p.ID,
		SSID:       ssidHex,
		ECDSA:      ecdsaHex,
		Parameters: *p.Pedersen,
	}
	return json.Marshal(x)
}

func (p *Public) UnmarshalJSON(bytes []byte) error {
	var x jsonParty
	err := json.Unmarshal(bytes, &x)
	if err != nil {
		return err
	}

	ssid, err := hex.DecodeString(x.SSID)
	if err != nil {
		return err
	}
	ecdsaBytes, err := hex.DecodeString(x.ECDSA)
	if err != nil {
		return err
	}
	ecdsa, err := curve.NewIdentityPoint().SetBytes(ecdsaBytes)
	if err != nil {
		return err
	}
	p.ID = x.ID
	p.SSID = ssid
	p.ECDSA = ecdsa
	p.Paillier = paillier.NewPublicKey(x.N)
	p.Pedersen = &x.Parameters
	return p.Validate()
}
