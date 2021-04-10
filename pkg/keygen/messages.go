package keygen

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
)

type (
	// Figure 5

	message1 struct {
		V []byte // Vᵢ = H(sid, i, ridᵢ, Xᵢ, Aᵢ, uᵢ)
	}

	message2 struct {
		RID []byte       // ridᵢ <- {0,1}ᵏ
		X   *curve.Point // Xᵢ = [xᵢ]•G
		A   *curve.Point // Schnorr commitment: Aᵢ = [aᵢ]•G
		U   []byte       // uᵢ <- {0,1}ᵏ = nonce for Vᵢ
	}

	message3 struct {
		Z *curve.Scalar // zᵢ = aᵢ + H(sid, i, rid, Aᵢ) * xᵢ (mod q)
	}
)

// TODO Methods for creating PB messages from the inputs.
