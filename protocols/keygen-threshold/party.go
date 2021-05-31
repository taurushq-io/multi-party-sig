package keygen_threshold

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"

	//"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

// localParty is the state we store for a remote party.
// The messages are embedded to make access to the attributes easier.
type localParty struct {
	*round.Party

	//X []*curve.Point // Xⱼ
	// A are the schnorr commitments to the polynomial in the exponent
	A []*curve.Point // Aⱼ

	//Y    *curve.Point
	//BSch *curve.Point

	commitment hash.Commitment // H(msg2, decommitment)

	rho []byte // ρᵢ

	polyExp *polynomial.Exponent

	shareReceived *curve.Scalar
}
