package session

import (
	"math/big"
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
)

func TestSession_Commit(t *testing.T) {
	config, err := NewConfig(1, []uint32{1, 2})
	if err != nil {
		t.Error(err)
	}
	s, err := New(config)
	if err != nil {
		t.Error(err)
	}
	v1 := big.NewInt(346)
	v2 := map[uint32]*curve.Point{1: curve.NewIdentityPoint().ScalarBaseMult(curve.NewScalarRandom())}
	c, d, err := s.Commit(1, v1, v2)
	if err != nil {
		t.Error(err)
	}
	if !s.Decommit(1, c, d, v1, v2) {
		t.Errorf("failed to decommit")
	}
}
