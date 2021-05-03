package zklogstar

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

type (
	Public struct {
		// C = Enc₀(x;ρ)
		// Encryption of x under the prover's key
		C *paillier.Ciphertext

		// X = [x] G
		// x "in the exponent"
		X *curve.Point

		// G = Base point of the curve,
		// If G = nil, the default base point is used
		G *curve.Point

		Prover *paillier.PublicKey
		Aux    *pedersen.Parameters
	}
	Private struct {
		// X is the plaintext of C and the dlog of X
		X *big.Int

		// Rho = ρ
		// nonce of C
		Rho *big.Int
	}
	Commitment struct {
		// S = sˣ tᵘ
		S *big.Int

		// A = En c₀(alpha; r)
		A *paillier.Ciphertext

		// Y = gᵃ
		Y *curve.Point

		// D = sᵃ tᵍ
		D *big.Int
	}
)

func (public Public) Prove(hash *hash.Hash, private Private) (*pb.ZKLogStar, error) {
	N := public.Prover.N()

	if public.G == nil {
		public.G = curve.NewBasePoint()
	}

	alpha := sample.IntervalLEps()
	r := sample.UnitModN(N)
	mu := sample.IntervalLN()
	gamma := sample.IntervalLEpsN()

	S := public.Aux.Commit(private.X, mu)
	A, _ := public.Prover.Enc(alpha, r)
	Y := curve.NewIdentityPoint().ScalarMult(curve.NewScalarBigInt(alpha), public.G)
	D := public.Aux.Commit(alpha, gamma)

	e, err := challenge(hash, public, Commitment{
		A: A,
		Y: Y,
		S: S,
		D: D,
	})
	if err != nil {
		return nil, err
	}

	var z1, z2, z3 big.Int
	// z1 = α + e x
	z1.Mul(e, private.X)
	z1.Add(&z1, alpha)

	// z2 = r ρᵉ mod Nₐ
	z2.Exp(private.Rho, e, N)
	z2.Mul(&z2, r)
	z2.Mod(&z2, N)

	// z3 = γ + e μ
	z3.Mul(e, mu)
	z3.Add(&z3, gamma)

	return &pb.ZKLogStar{
		S:  pb.NewInt(S),
		A:  pb.NewCiphertext(A),
		Y:  pb.NewPoint(Y),
		D:  pb.NewInt(D),
		Z1: pb.NewInt(&z1),
		Z2: pb.NewInt(&z2),
		Z3: pb.NewInt(&z3),
	}, nil
}

func (public Public) Verify(hash *hash.Hash, proof *pb.ZKLogStar) bool {
	if !proof.IsValid() {
		return false
	}

	if public.G == nil {
		public.G = curve.NewBasePoint()
	}

	prover := public.Prover

	S := proof.GetS().Unmarshal()
	A := proof.GetA().Unmarshal()
	Y, err := proof.GetY().Unmarshal()
	if err != nil {
		return false
	}
	D := proof.GetD().Unmarshal()

	e, err := challenge(hash, public, Commitment{
		A: A,
		Y: Y,
		S: S,
		D: D,
	})
	if err != nil {
		return false
	}

	z1, z2, z3 := proof.Z1.Unmarshal(), proof.Z2.Unmarshal(), proof.Z3.Unmarshal()

	if !arith.IsInIntervalLPrimeEps(z1) {
		return false
	}

	var rhsCt paillier.Ciphertext
	lhsCt, _ := prover.Enc(z1, z2)
	rhsCt.Mul(prover, public.C, e)
	rhsCt.Add(prover, &rhsCt, A)
	if !lhsCt.Equal(&rhsCt) {
		return false
	}

	lhs := curve.NewIdentityPoint().ScalarMult(curve.NewScalarBigInt(e), public.X) // reuse lhs
	rhs := curve.NewIdentityPoint().Add(Y, lhs)

	lhs.ScalarMult(curve.NewScalarBigInt(z1), public.G)
	if lhs.Equal(rhs) != 1 {
		return false
	}

	if !public.Aux.Verify(z1, z3, D, S, e) {
		return false
	}

	return true
}

func challenge(hash *hash.Hash, public Public, commitment Commitment) (*big.Int, error) {
	err := hash.WriteAny(public.Aux, public.Prover, public.C, public.X, public.G,
		commitment.S, commitment.A, commitment.Y, commitment.Y)
	if err != nil {
		return nil, err
	}

	return hash.ReadFqNegative()
}
