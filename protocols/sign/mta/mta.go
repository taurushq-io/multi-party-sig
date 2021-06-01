package mta

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
	zkaffg "github.com/taurusgroup/cmp-ecdsa/pkg/zk/affg"
)

type MtA struct {
	// Beta is βᵢⱼ
	Beta *curve.Scalar
	// D is Dⱼᵢ = (⋅ᵢ ⊙ Kⱼ) ⊕ encⱼ(- βᵢⱼ, sᵢⱼ)
	D *paillier.Ciphertext
	// F is Fⱼᵢ = encᵢ(βᵢⱼ, rᵢⱼ)
	F *paillier.Ciphertext

	// randD is the Paillier randomness sᵢⱼ for Dⱼᵢ = (⋅ᵢ ⊙ Kⱼ) ⊕ encⱼ(- βᵢⱼ, sᵢⱼ)
	randD *big.Int
	// randF is the Paillier randomness rᵢⱼ for Fⱼᵢ = encᵢ(βᵢⱼ, rᵢⱼ)
	randF *big.Int

	// sender and receiver are kept her to make the proving easier
	sender, receiver *paillier.PublicKey

	// encKj = Kⱼ = Encⱼ(kⱼ, •)
	encKj *paillier.Ciphertext

	// betaNeg = - βᵢⱼ
	betaNeg *big.Int

	// secretI is the prover's multiplicative share
	secretI *curve.Scalar
}

func New(secretI *curve.Scalar, Kj *paillier.Ciphertext, paillierJ, paillierI *paillier.PublicKey) *MtA {

	betaNeg := sample.IntervalLPrime()

	F, r := paillierI.Enc(betaNeg, nil)

	D, s := paillierJ.Enc(betaNeg, nil)
	tempC := paillier.NewCiphertext().Mul(paillierJ, Kj, secretI.BigInt())
	D.Add(paillierJ, tempC, D)

	Beta := curve.NewScalar().SetBigInt(betaNeg.Neg(betaNeg))

	// set β back to non neg
	return &MtA{
		randD:    s,
		randF:    r,
		Beta:     Beta,
		D:        D,
		F:        F,
		sender:   paillierI,
		receiver: paillierJ,
		encKj:    Kj,
		betaNeg:  betaNeg.Neg(betaNeg),
		secretI:  secretI,
	}
}

func (m *MtA) ProveAffG(publicI *curve.Point, h *hash.Hash, aux *pedersen.Parameters) (*pb.ZKAffG, error) {
	zkPublic := zkaffg.Public{
		C:        m.encKj,
		D:        m.D,
		Y:        m.F,
		X:        publicI,
		Prover:   m.sender,
		Verifier: m.receiver,
		Aux:      aux,
	}
	zkPrivate := zkaffg.Private{
		X:    m.secretI.BigInt(),
		Y:    m.betaNeg,
		Rho:  m.randD,
		RhoY: m.randF,
	}

	return zkPublic.Prove(h, zkPrivate)
}
