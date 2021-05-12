package mta

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	zkaffg "github.com/taurusgroup/cmp-ecdsa/pkg/sign/affg"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
)

func Test_newMtA(t *testing.T) {
	verifierPaillier := zk.VerifierPaillierPublic
	verifierPaillierSecret := zk.VerifierPaillierSecret
	verifierPedersen := zk.Pedersen
	proverPaillier := zk.ProverPaillierPublic

	gammaI := curve.NewScalarRandom()
	GammaI := curve.NewIdentityPoint().ScalarBaseMult(gammaI)

	kj := curve.NewScalarRandom()
	Kj, _ := verifierPaillier.Enc(kj.BigInt(), nil)

	m := New(gammaI, Kj, verifierPaillier, proverPaillier)
	p, err := m.ProveAffG(GammaI, hash.New(nil), verifierPedersen)
	if err != nil {
		t.Error(err)
		return
	}

	zkPublic := zkaffg.Public{
		C:        Kj,
		D:        m.D,
		Y:        m.F,
		X:        GammaI,
		Prover:   proverPaillier,
		Verifier: verifierPaillier,
		Aux:      verifierPedersen,
	}
	if !zkPublic.Verify(hash.New(nil), p) {
		t.Error("affg failed")
		return
	}

	gammaIkJ := curve.NewScalar().Multiply(gammaI, kj)

	alpha := verifierPaillierSecret.Dec(m.D)
	alphaS := curve.NewScalar().SetBigInt(alpha)

	alphaPlusBeta := curve.NewScalar().Add(alphaS, m.Beta)
	if !gammaIkJ.Equal(alphaPlusBeta) {
		t.Error("MtA bad")
		return
	}
}
