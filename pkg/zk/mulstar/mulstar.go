package zkmulstar

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
)

type (
	Public struct {
		// C = Enc₀(?;?)
		C *paillier.Ciphertext

		// D = (x ⨀ C) ⨁ Enc₀(y;ρ)
		D *paillier.Ciphertext

		// X = gˣ
		X *curve.Point

		// Verifier = N₀
		Verifier *paillier.PublicKey
		Aux      *pedersen.Parameters
	}
	Private struct {
		// X ∈ ± 2ˡ
		X *big.Int

		// Rho = ρ = Nonce D
		Rho *big.Int
	}
)

type Commitment struct {
	// A = (α ⊙ C ) ⊕ Enc₀(β; r)
	A *paillier.Ciphertext

	// Bx = [α] G
	Bx *curve.Point

	// E = sᵃ tᵍ
	// S = sˣ tᵐ
	E, S *big.Int
}

func (public Public) Prove(hash *hash.Hash, private Private) (*pb.ZKMulStar, error) {
	N0 := public.Verifier.N

	verifier := public.Verifier

	alpha := sample.IntervalLEps()

	r := sample.UnitModN(N0)

	gamma := sample.IntervalLEpsN()
	m := sample.IntervalLEpsN()

	A := paillier.NewCiphertext()
	A.Mul(verifier, public.C, alpha)
	A.Randomize(verifier, r)

	var Bx curve.Point
	Bx.ScalarBaseMult(curve.NewScalarBigInt(alpha))

	commitment := Commitment{
		A:  A,
		Bx: &Bx,
		E:  public.Aux.Commit(alpha, gamma),
		S:  public.Aux.Commit(private.X, m),
	}

	e, err := challenge(hash, public, commitment)
	if err != nil {
		return nil, err
	}

	return &pb.ZKMulStar{
		A:  pb.NewCiphertext(A),
		Bx: pb.NewPoint(&Bx),
		E:  pb.NewInt(commitment.E),
		S:  pb.NewInt(commitment.S),
		Z1: zk.Affine(alpha, e, private.X),
		Z2: zk.Affine(gamma, e, m),
		W:  zk.AffineNonce(r, private.Rho, e, verifier),
	}, nil
}

func (public Public) Verify(hash *hash.Hash, proof *pb.ZKMulStar) bool {
	if !proof.IsValid() {
		return false
	}

	verifier := public.Verifier

	z1, z2 := proof.Z1.Unmarshal(), proof.Z2.Unmarshal()
	w := proof.GetW().Unmarshal()

	if !arith.IsInIntervalLEps(z1) {
		return false
	}

	Bx, err := proof.GetBx().Unmarshal()
	if err != nil {
		return false
	}

	A := proof.GetA().Unmarshal()

	E, S := proof.GetE().Unmarshal(), proof.GetS().Unmarshal()

	e, err := challenge(hash, public, Commitment{
		A:  A,
		Bx: Bx,
		E:  E,
		S:  S,
	})
	if err != nil {
		return false
	}

	var lhsCt, rhsCt paillier.Ciphertext
	{
		// lhsCt = z₁ ⊙ C + rand
		lhsCt.Mul(verifier, public.C, z1)
		lhsCt.Randomize(verifier, w)

		// rhsCt = A ⊕ (e ⊙ D)
		rhsCt.Mul(verifier, public.D, e)
		rhsCt.Add(verifier, &rhsCt, A)

		if !lhsCt.Equal(&rhsCt) {
			return false
		}
	}

	{
		var lhsPt, rhsPt curve.Point
		lhsPt.ScalarBaseMult(curve.NewScalarBigInt(z1))
		rhsPt.ScalarMult(curve.NewScalarBigInt(e), public.X)
		rhsPt.Add(&rhsPt, Bx)
		if !lhsPt.Equal(&rhsPt) {
			return false
		}
	}

	if !public.Aux.Verify(z1, z2, E, S, e) {
		return false
	}

	return true
}

func challenge(hash *hash.Hash, public Public, commitment Commitment) (*big.Int, error) {

	err := hash.WriteAny(public.Aux, public.Verifier,
		public.C, public.D, public.X,
		commitment.A, commitment.Bx,
		commitment.E, commitment.S)
	if err != nil {
		return nil, err
	}

	return hash.ReadFqNegative()
}

//// NewProof generates a proof that the
//// x ∈ ±2^l
//// gˣ = X
//// D = (alpha ⊙ c ) • rho^N0
//func NewProof(proverPailler *paillier.PublicKey, verifierPedersen *pedersen.Parameters, C, D *paillier.Ciphertext, X *curve.Point,
//	x, rho *big.Int) *Proof {
//	alpha := sample.PlusMinus(params.LPlusEpsilon, false)
//	r := proverPailler.Nonce()
//	gamma := sample.PlusMinus(params.LPlusEpsilon, true)
//	m := sample.PlusMinus(params.L, true)
//
//	var A paillier.Ciphertext
//	A.Mul(proverPailler, C, alpha)
//	A.Randomize(proverPailler, r)
//
//	var Bx curve.Point
//	Bx.ScalarBaseMult(curve.NewScalarBigInt(alpha))
//
//	commitment := &Commitment{
//		A:  &A,
//		Bx: &Bx,
//		E:  verifierPedersen.Commit(alpha, gamma),
//		S:  verifierPedersen.Commit(x, m),
//	}
//
//	e := commitment.Challenge()
//
//	var z1, z2, w big.Int
//	z1.Mul(e, x)
//	z1.Add(&z1, alpha)
//
//	z2.Mul(e, m)
//	z2.Add(&z2, gamma)
//
//	N0 := proverPailler.N
//	w.Exp(rho, e, N0)
//	w.Mul(&w, r)
//	w.Mod(&w, N0)
//
//	response := &Response{
//		Z1: &z1,
//		Z2: &z2,
//		W:  &w,
//	}
//
//	return &Proof{
//		Commitment: commitment,
//		Response:   response,
//	}
//}
//
//func (proof *Proof) Verify(proverPailler *paillier.PublicKey, verifierPedersen *pedersen.Parameters, C, D *paillier.Ciphertext, X *curve.Point) bool {
//	if !sample.IsInInterval(proof.Z1, params.LPlusEpsilon) {
//		return false
//	}
//
//	e := proof.Challenge()
//
//	{
//		var lhs, rhs paillier.Ciphertext
//		// lhs = c^z1 w^N0
//		lhs.Mul(proverPailler, C, proof.Z1)
//		lhs.Randomize(proverPailler, proof.W)
//
//		// rhs = A D^e
//		rhs.Mul(proverPailler, D, e)
//		rhs.Add(proverPailler, &rhs, proof.A)
//
//		if !lhs.Equal(&rhs) {
//			return false
//		}
//	}
//
//	{
//		var lhs, rhs curve.Point
//		// lhs = g^z1
//		lhs.ScalarBaseMult(curve.NewScalarBigInt(proof.Z1))
//
//		// rhs = Bx X^e
//		rhs.ScalarMult(curve.NewScalarBigInt(e), X)
//		rhs.Add(&rhs, proof.Bx)
//		if lhs.Equal(&rhs) != 1 {
//			return false
//		}
//	}
//
//	{
//		if !verifierPedersen.Verify(proof.Z1, proof.Z2, proof.E, proof.S, e) {
//			return false
//		}
//	}
//
//	return true
//}
