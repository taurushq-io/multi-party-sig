package zkenc

import (
	"fmt"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

type (
	Public struct {
		// K = Enc₀(k;ρ)
		K *paillier.Ciphertext

		Prover *paillier.PublicKey
		Aux    *pedersen.Parameters
	}
	Private struct {
		// K = k ∈ 2ˡ = Dec₀(K)
		// plaintext of K
		K *big.Int

		// Rho = ρ
		// nonce of K
		Rho *big.Int
	}
)

type Commitment struct {
	// A = Enc(α; r)
	A *paillier.Ciphertext

	// S = sᵏ t^mu
	// C = s^alpha t^gamma
	S, C *big.Int
}

func (public Public) Prove(hash *hash.Hash, private Private) (*pb.ZKEnc, error) {
	N := public.Prover.N()

	alpha := sample.IntervalLEps()
	r := sample.UnitModN(N)
	mu := sample.IntervalLN()
	gamma := sample.IntervalLEpsN()

	S := public.Aux.Commit(private.K, mu)
	A, _ := public.Prover.Enc(alpha, r)
	C := public.Aux.Commit(alpha, gamma)

	e, err := challenge(hash, public, Commitment{
		A: A,
		S: S,
		C: C,
	})
	if err != nil {
		return nil, err
	}

	var z1, z2, z3 big.Int
	z1.Mul(e, private.K)
	z1.Add(&z1, alpha)

	z2.Exp(private.Rho, e, N)
	z2.Mul(&z2, r)
	z2.Mod(&z2, N)

	z3.Mul(e, mu)
	z3.Add(&z3, gamma)

	return &pb.ZKEnc{
		S:  pb.NewInt(S),
		A:  pb.NewCiphertext(A),
		C:  pb.NewInt(C),
		Z1: pb.NewInt(&z1),
		Z2: pb.NewInt(&z2),
		Z3: pb.NewInt(&z3),
	}, nil
}

func (public Public) Verify(hash *hash.Hash, proof *pb.ZKEnc) bool {
	if !proof.IsValid() {
		return false
	}

	prover := public.Prover

	A := proof.GetA().Unmarshal()
	S := proof.GetS().Unmarshal()
	C := proof.GetC().Unmarshal()

	e, err := challenge(hash, public, Commitment{
		A: A,
		S: S,
		C: C,
	})
	if err != nil {
		return false
	}

	z1, z2, z3 := proof.Z1.Unmarshal(), proof.Z2.Unmarshal(), proof.Z3.Unmarshal()

	var rhsCt paillier.Ciphertext
	lhsCt, _ := prover.Enc(z1, z2)
	rhsCt.Mul(prover, public.K, e)
	rhsCt.Add(prover, &rhsCt, A)
	if !lhsCt.Equal(&rhsCt) {
		fmt.Println("fail ct")
		return false
	}

	if !public.Aux.Verify(z1, z3, C, S, e) {
		fmt.Println("fail ped")
		return false
	}

	return true
}

func challenge(hash *hash.Hash, public Public, commitment Commitment) (*big.Int, error) {
	var err error

	err = hash.WriteAny(public.Aux, public.Prover, public.K,
		commitment.S, commitment.A, commitment.C)
	if err != nil {
		return nil, err
	}

	return hash.ReadIntInInterval(params.L)
}
