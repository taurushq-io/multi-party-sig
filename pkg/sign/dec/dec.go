package zkdec

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

type (
	Public struct {
		// C = Enc₀(y;ρ)
		C *paillier.Ciphertext

		// X = y (mod q)
		X *curve.Scalar

		// Prover = N₀
		Prover *paillier.PublicKey
		Aux    *pedersen.Parameters
	}
	Private struct {
		// Y = y
		Y *big.Int

		// Rho = ρ
		Rho *big.Int
	}
)

type Commitment struct {
	// S = sʸ tᵘ
	// T = sᵃ tᵛ
	S, T *big.Int

	// A = Enc₀(α; r)
	A *paillier.Ciphertext

	// Gamma = alpha (mod q)
	Gamma *curve.Scalar
}

type Response struct {
	// Z1 = α + e•y
	// Z2 = ν + e•μ
	// W  = r ρ ᵉ (mod N₀)
	Z1, Z2, W *big.Int
}

func (public Public) Prove(hash *hash.Hash, private Private) (*pb.ZKDec, error) {
	N0 := public.Prover.N

	alpha := sample.IntervalLEps()

	mu := sample.IntervalLN()
	nu := sample.IntervalLEpsN()
	r := sample.UnitModN(N0)

	A, _ := public.Prover.Enc(alpha, r)

	gamma := curve.NewScalarBigInt(alpha)

	commitment := Commitment{
		S:     public.Aux.Commit(private.Y, mu),
		T:     public.Aux.Commit(alpha, nu),
		A:     A,
		Gamma: gamma,
	}

	e, err := challenge(hash, public, commitment)
	if err != nil {
		return nil, err
	}

	z1 := new(big.Int).Mul(e, private.Y)
	z1.Add(z1, alpha)

	z2 := new(big.Int).Mul(e, mu)
	z2.Add(z2, nu)

	w := new(big.Int).Exp(private.Rho, e, N0)
	w.Mul(w, r)
	w.Mod(w, N0)

	return &pb.ZKDec{
		S:     pb.NewInt(commitment.S),
		T:     pb.NewInt(commitment.T),
		A:     pb.NewCiphertext(A),
		Gamma: pb.NewScalar(gamma),
		Z1:    pb.NewInt(z1),
		Z2:    pb.NewInt(z2),
		W:     pb.NewInt(w),
	}, nil
}

func (public Public) Verify(hash *hash.Hash, proof *pb.ZKDec) bool {
	if !proof.IsValid() {
		return false
	}

	S, T := proof.GetS().Unmarshal(), proof.GetT().Unmarshal()
	A := proof.GetA().Unmarshal()
	gamma := proof.GetGamma().Unmarshal()
	z1, z2, w := proof.Z1.Unmarshal(), proof.Z2.Unmarshal(), proof.GetW().Unmarshal()

	e, err := challenge(hash, public, Commitment{
		S:     S,
		T:     T,
		A:     A,
		Gamma: gamma,
	})
	if err != nil {
		return false
	}

	lhsCt, _ := public.Prover.Enc(z1, w)
	rhsCt := paillier.NewCiphertext().Mul(public.Prover, public.C, e)
	rhsCt.Add(public.Prover, rhsCt, A)
	if !lhsCt.Equal(rhsCt) {
		return false
	}

	lhs := curve.NewScalarBigInt(z1)
	rhs := curve.NewScalarBigInt(e)
	rhs.MultiplyAdd(rhs, public.X, gamma)
	if !lhs.Equal(rhs) {
		return false
	}

	if !public.Aux.Verify(z1, z2, T, S, e) {
		return false
	}

	return true
}

func challenge(hash *hash.Hash, public Public, commitment Commitment) (*big.Int, error) {
	err := hash.WriteAny(public.Aux, public.Prover,
		public.C, public.X,
		commitment.S, commitment.T, commitment.A, commitment.Gamma)
	if err != nil {
		return nil, err
	}

	return hash.ReadFqNegative()
}
