package keygen

import (
	"bytes"
	"crypto/rand"
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

type Parameters struct {
	// PrivateECDSA the share of the final key
	PrivateECDSA *curve.Scalar

	// a is the random a ∈ 𝔽 used to prove knowledge of PrivateECDSA
	a *curve.Scalar

	// rid is the random id chosen by this party
	rid []byte
}

// Verify makes sure that the parameters are compatible with the configuration
func (p *Parameters) Verify() error {
	if p.PrivateECDSA != nil && p.PrivateECDSA.IsZero() {
		return errors.New("PrivateECDSA is zero")
	}
	return nil
}

func (p *Parameters) verify() bool {
	if p.a == nil || p.a.IsZero() {
		return false
	}
	if len(p.rid) != params.SecBytes || bytes.Equal(p.rid, make([]byte, params.SecBytes)) {
		return false
	}
	return true
}

func (p *Parameters) fill() {
	if p.PrivateECDSA == nil {
		p.PrivateECDSA = curve.NewScalarRandom()
	}
	if p.a == nil {
		p.a = curve.NewScalarRandom()
	}
	if p.rid == nil {
		p.rid = make([]byte, params.SecBytes)
		_, _ = rand.Read(p.rid)
	}
}
