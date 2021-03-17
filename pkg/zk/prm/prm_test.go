package zkprm

import (
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk/pedersen"
)

func TestMod(t *testing.T) {
	_, _, n, phi := sample.Paillier()
	v, lambda := pedersen.NewPedersen(n, phi)
	p := NewProof(v, lambda, phi)
	if !p.Verify(v) {
		t.Error("failed")
	}
}
