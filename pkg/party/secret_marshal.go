package party

import (
	"encoding/hex"
	"encoding/json"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
)

var _ json.Marshaler = (*Secret)(nil)
var _ json.Unmarshaler = (*Secret)(nil)

type jsonSecret struct {
	ID       ID                 `json:"id"`
	ECDSA    string             `json:"ecdsa"`
	Paillier paillier.SecretKey `json:"paillier"`
	RID      string             `json:"rid"`
}

func (s Secret) MarshalJSON() ([]byte, error) {
	ridHex := hex.EncodeToString(s.RID)
	ecdsaHex := hex.EncodeToString(s.ECDSA.Bytes())
	x := jsonSecret{
		ID:       s.ID,
		ECDSA:    ecdsaHex,
		Paillier: *s.Paillier,
		RID:      ridHex,
	}
	return json.Marshal(x)
}

func (s *Secret) UnmarshalJSON(bytes []byte) error {
	var x jsonSecret
	err := json.Unmarshal(bytes, &x)
	if err != nil {
		return err
	}

	rid, err := hex.DecodeString(x.RID)
	if err != nil {
		return err
	}
	ecdsaBytes, err := hex.DecodeString(x.ECDSA)
	if err != nil {
		return err
	}
	ecdsa := curve.NewScalar().SetBytes(ecdsaBytes)

	s.ID = x.ID
	s.ECDSA = ecdsa
	s.Paillier = &x.Paillier
	s.RID = rid
	return s.Validate()
}
