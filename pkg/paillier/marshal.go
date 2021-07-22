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
	P []byte `json:"p"`
	Q []byte `json:"q"`
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
	return json.Marshal(jsonPublicKey{N: pk.n.Big()})
}

func (sk *SecretKey) UnmarshalJSON(bytes []byte) error {
	var x jsonSecretKey
	err := json.Unmarshal(bytes, &x)
	if err != nil {
		return err
	}
	*sk = *NewSecretKeyFromPrimes(new(big.Int).SetBytes(x.P), new(big.Int).SetBytes(x.Q))
	return nil
}

func (sk SecretKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonSecretKey{
		P: sk.P().Bytes(),
		Q: sk.Q().Bytes(),
	})
}
