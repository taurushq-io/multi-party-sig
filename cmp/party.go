package cmp

import (
	"github.com/taurusgroup/cmp-ecdsa/paillier"
	"github.com/taurusgroup/cmp-ecdsa/zk"
	"go.dedis.ch/kyber/v3"
)

type Party struct {
	ID       int
	Paillier *paillier.PublicKey
	ECDSA    kyber.Point
	Pedersen *zk.Pedersen
}

type PartySecret struct {
	Paillier *paillier.SecretKey
	ECDSA    kyber.Scalar
}

type signParty struct {
	*Party

	K *paillier.Ciphertext // K_j = Enc_j (k_j)
	G *paillier.Ciphertext // Enc_j (𝝲_j)

	Gamma kyber.Point // 𝞒_j

	// MtA shares
	alpha, beta       kyber.Scalar // 𝞪_ij = Dec_i(D_ij), 𝞫_ij
	alphaHat, betaHat kyber.Scalar // 𝞪_ij = Dec_i(DHat_ij), 𝞫_ij

	delta kyber.Scalar // 𝞭_j
	Delta kyber.Point  // 𝞓_j

	// sigma is the signature share sent out in round4
	sigma kyber.Scalar // 𝞂_j = k_j m + r 𝟀_j
}

func NewParty(id int) (party *Party, secret *PartySecret) {
	ecdsaSecret := suite.Scalar().Pick(suite.RandomStream())
	ecdsaPublic := suite.Point().Mul(ecdsaSecret, nil)

	paillierPublic, paillierSecret := paillier.KeyGen(256)

	secret = &PartySecret{
		Paillier: paillierSecret,
		ECDSA:    ecdsaSecret,
	}

	party = &Party{
		ID:       id,
		Paillier: paillierPublic,
		ECDSA:    ecdsaPublic,
		Pedersen: zk.NewPedersen(paillierPublic.N(), paillierSecret.Phi()),
	}
	return
}
