package zkmul

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zk"
)

type (
	Public struct {
		// X = Enc(x; ρₓ)
		X *paillier.Ciphertext

		// Y = Enc(?;?)
		Y *paillier.Ciphertext

		// C = x ⊙ Y % ρ
		C *paillier.Ciphertext

		// Prover = N
		Prover *paillier.PublicKey
	}
	Private struct {
		// X enc of X
		X *big.Int

		// Rho = Nonce C = ρ
		Rho *big.Int

		// RhoX = Nonce X = ρₓ
		RhoX *big.Int
	}
)

type Commitment struct {
	// A = α ⊙ Y % ρ
	A *paillier.Ciphertext

	// B = Enc(α;s)
	B *paillier.Ciphertext
}

func (public Public) Prove(hash *hash.Hash, private Private) (*pb.ZKMul, error) {
	N := public.Prover.N

	prover := public.Prover

	alpha := sample.UnitModN(N)
	r := sample.UnitModN(N)
	s := sample.UnitModN(N)

	A := paillier.NewCiphertext().Mul(prover, public.Y, alpha)
	A.Randomize(prover, r)

	B, _ := prover.Enc(alpha, s)

	e, err := challenge(hash, public, Commitment{
		A: A,
		B: B,
	})
	if err != nil {
		return nil, err
	}

	return &pb.ZKMul{
		A: pb.NewCiphertext(A),
		B: pb.NewCiphertext(B),
		Z: zk.Affine(alpha, e, private.X),
		U: zk.AffineNonce(r, private.Rho, e, prover),
		V: zk.AffineNonce(s, private.RhoX, e, prover),
	}, nil
}

func (public Public) Verify(hash *hash.Hash, proof *pb.ZKMul) bool {
	if !proof.IsValid() {
		return false
	}

	prover := public.Prover

	A, B := proof.GetA().Unmarshal(), proof.GetB().Unmarshal()
	z, u, v := proof.GetZ().Unmarshal(), proof.GetU().Unmarshal(), proof.GetV().Unmarshal()

	e, err := challenge(hash, public, Commitment{
		A: A,
		B: B,
	})
	if err != nil {
		return false
	}

	lhsCt, rhsCt := paillier.NewCiphertext(), paillier.NewCiphertext()
	lhsCt.Mul(prover, public.Y, z)
	lhsCt.Randomize(prover, u)
	rhsCt.Mul(prover, public.C, e)
	rhsCt.Add(prover, rhsCt, A)
	if !lhsCt.Equal(rhsCt) {
		return false
	}

	lhsCt.Enc(prover, z, v)
	rhsCt.Mul(prover, public.X, e)
	rhsCt.Add(prover, rhsCt, B)
	if !lhsCt.Equal(rhsCt) {
		return false
	}

	return true
}

func challenge(hash *hash.Hash, public Public, commitment Commitment) (*big.Int, error) {

	err := hash.WriteAny(public.Prover,
		public.X, public.Y, public.C,
		commitment.A, commitment.B)
	if err != nil {
		return nil, err
	}

	return hash.ReadFqNegative()
}

//// NewProof generates a proof that the
//func NewProof(verifier *paillier.PublicKey, X, Y, C *paillier.Ciphertext,
//	x *big.Int, rho, rhoX *big.Int) *Proof {
//	N := verifier.N
//
//	alpha := sample.UnitModN(N)
//
//	var A, B paillier.Ciphertext
//
//	A.Mul(verifier, Y, alpha)
//	_, r := A.Randomize(verifier, nil)
//
//	_, s := B.Enc(verifier, alpha, nil)
//
//	commitment := &Commitment{
//		A: &A,
//		B: &B,
//	}
//
//	e := commitment.Challenge()
//
//	var z, u, v big.Int
//	z.Mul(e, x)
//	z.Add(&z, alpha)
//
//	u.Exp(rho, e, N)
//	u.Mul(&u, r)
//
//	v.Exp(rhoX, e, N)
//	v.Mul(&v, s)
//	v.Mod(&v, N)
//
//	response := &Response{
//		Z: &z,
//		U: &u,
//		V: &v,
//	}
//
//	return &Proof{
//		Commitment: commitment,
//		Response:   response,
//	}
//}
//
//func (proof *Proof) Verify(prover *paillier.PublicKey, X, Y, C *paillier.Ciphertext) bool {
//	e := proof.Challenge()
//
//	var lhs, rhs paillier.Ciphertext
//
//	{
//		// lhs = Y^z u^N
//		lhs.Mul(prover, Y, proof.Z)
//		lhs.Randomize(prover, proof.U)
//
//		// rhs = A c^e
//		rhs.Mul(prover, C, e)
//		rhs.Add(prover, &rhs, proof.A)
//
//		if !lhs.Equal(&rhs) {
//			return false
//		}
//	}
//
//	{
//		// lhs = Enc(z; v)
//		lhs.Enc(prover, proof.Z, proof.V)
//
//		// rhs = B X^e
//		rhs.Mul(prover, X, e)
//		rhs.Add(prover, &rhs, proof.B)
//		if !lhs.Equal(&rhs) {
//			return false
//		}
//	}
//
//	return true
//}
