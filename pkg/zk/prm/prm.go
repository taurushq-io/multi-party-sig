package zkprm

import (
	"fmt"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

type (
	// Public is the
	Public struct {
		Pedersen *pedersen.Parameters
	}
	Private struct {
		Lambda, Phi *big.Int
	}
)

// Prove generates a proof that:
// s = t^lambda (mod N)
func (public Public) Prove(hash *hash.Hash, private Private) (*pb.ZKPrm, error) {
	var err error
	n := public.Pedersen.N
	phi := private.Phi

	A := make([]*pb.Int, params.StatParam)
	a := make([]*big.Int, params.StatParam)

	Atemp := new(big.Int)
	for i := 0; i < params.StatParam; i++ {
		a[i] = sample.IntervalLN()
		a[i].Mod(a[i], phi)
		Atemp.Exp(public.Pedersen.T, a[i], n)
		A[i] = pb.NewInt(Atemp)
	}

	es, err := challenge(hash, public, A)
	if err != nil {
		return nil, fmt.Errorf("zkprm: prove: %w", err)
	}

	z := new(big.Int)
	Z := make([]*pb.Int, params.StatParam)
	for i := 0; i < params.StatParam; i++ {
		z.Set(a[i])
		if es[i] {
			z.Add(z, private.Lambda)
			z.Mod(z, phi)
		}
		Z[i] = pb.NewInt(z)
	}

	return &pb.ZKPrm{
		A: A,
		Z: Z,
	}, nil
}

func (public Public) Verify(hash *hash.Hash, proof *pb.ZKPrm) bool {
	var err error

	if !proof.IsValid() {
		return false
	}
	if !public.Pedersen.IsValid() {
		return false
	}

	n, s, t := public.Pedersen.N, public.Pedersen.S, public.Pedersen.T

	es, err := challenge(hash, public, proof.A)
	if err != nil {
		return false
	}

	var lhs, rhs big.Int
	one := big.NewInt(1)
	z, a := new(big.Int), new(big.Int)
	for i := 0; i < params.StatParam; i++ {
		z = proof.Z[i].Unmarshal()
		a = proof.A[i].Unmarshal()

		if a.Cmp(one) == 0 {
			return false
		}

		lhs.Exp(t, z, n)
		if es[i] {
			rhs.Mul(a, s)
			rhs.Mod(&rhs, n)
		} else {
			rhs.Set(a)
		}

		if lhs.Cmp(&rhs) != 0 {
			return false
		}
	}
	return true
}

func challenge(hash *hash.Hash, public Public, A []*pb.Int) (es []bool, err error) {
	if err = hash.WriteInt(public.Pedersen.N, public.Pedersen.S, public.Pedersen.T); err != nil {
		return nil, err
	}
	for _, a := range A {
		if _, err = hash.Write(a.Int); err != nil {
			return nil, err
		}
	}
	return hash.ReadBools(params.StatParam)

}
