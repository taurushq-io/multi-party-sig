package paillier

import (
	"encoding/json"
	"math/big"
)

var _ json.Marshaler = (*PublicKey)(nil)
var _ json.Unmarshaler = (*PublicKey)(nil)
var _ json.Marshaler = (*SecretKey)(nil)
var _ json.Unmarshaler = (*SecretKey)(nil)

type jsonPublicKey struct {
	N *big.Int `json:"n"`
}

type jsonSecretKey struct {
	P *big.Int `json:"p"`
	Q *big.Int `json:"q"`
}

func (pk *PublicKey) UnmarshalJSON(bytes []byte) error {
	var x jsonPublicKey
	err := json.Unmarshal(bytes, &x)
	if err != nil {
		return err
	}
	*pk = *NewPublicKey(x.N)
	return nil
}

func (pk PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonPublicKey{N: pk.n})
}

func (sk *SecretKey) UnmarshalJSON(bytes []byte) error {
	var x jsonSecretKey
	err := json.Unmarshal(bytes, &x)
	if err != nil {
		return err
	}
	*sk = *NewSecretKeyFromPrimes(x.P, x.Q)
	return nil
}

func (sk SecretKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonSecretKey{
		P: sk.P(),
		Q: sk.Q(),
	})
}
