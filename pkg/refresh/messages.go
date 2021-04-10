package refresh

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	zkmod "github.com/taurusgroup/cmp-ecdsa/pkg/refresh/mod"
	zkprm "github.com/taurusgroup/cmp-ecdsa/pkg/refresh/prm"
)

type (
	// Figure 5 d₁

	message1 struct {
		CommitMessage2 []byte // Vⱼ = H(ssid, j, ridⱼ, Xⱼ, Aⱼ, uⱼ)
	}

	message2 struct {
		X      map[uint32]*curve.Point // (Xⱼ)ₗ
		A      map[uint32]*curve.Point //
		Y      *curve.Point
		B      *curve.Point
		N      *big.Int
		S      *big.Int
		T      *big.Int
		Rho, U []byte
	}

	message3 struct {
		C *paillier.Ciphertext // C = encⱼ(x)

		Mod  *zkmod.Proof
		Prm  *zkprm.Proof
		SchX *curve.Scalar
		SchY *curve.Scalar
	}
)

// TODO Methods for creating PB messages from the inputs.
