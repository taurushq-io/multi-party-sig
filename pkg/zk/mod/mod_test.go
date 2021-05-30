package zkmod

import (
	"math/big"
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
)

func TestMod(t *testing.T) {
	p, q, n, phi := sample.Paillier()
	public := Public{N: n}
	p2, err := public.Prove(hash.New(), Private{
		P:   p,
		Q:   q,
		Phi: phi,
	})
	if err != nil {
		t.Error("failed")
		return
	}
	if !public.Verify(hash.New(), p2) {
		t.Error("failed")
	}
}

func Test_set4thRoot(t *testing.T) {
	var pInt, qInt int64 = 311, 331
	p := big.NewInt(311)
	q := big.NewInt(331)
	n := big.NewInt(pInt * qInt)
	phi := big.NewInt((pInt - 1) * (qInt - 1))
	y := big.NewInt(502)
	w := sample.QNR(n)

	a, b, x := makeQuadraticResidue(y, w, n, p, q)

	root := fourthRoot(x, phi, n)

	if b {
		y.Mul(y, w)
		y.Mod(y, n)
	}
	if a {
		y.Neg(y)
		y.Mod(y, n)
	}

	root.Exp(root, four, n)
	if root.Cmp(y) != 0 {
		t.Error("wrong root")
	}
}
