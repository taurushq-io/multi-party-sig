package zk

import (
	"errors"
	"fmt"
	"github.com/taurusgroup/cmp-ecdsa/arith"
	"github.com/taurusgroup/cmp-ecdsa/paillier"
	"go.dedis.ch/kyber/v3"
	"math/big"
)

type AffineGroupCommitmentRange struct {
	A, By, E, F, S, T *big.Int
	Bx                []byte

	Z1, Z2, Z3, Z4 *big.Int
	W, Wy          *big.Int
}

var ErrZKAffineGroupCommitmentRange = errors.New("zk: aff-g: verification failed")

// NewAffineGroupCommitmentRange computes a Zero Knowledge proof of the following statement:
//
// Public:
// N0 = NHat = NVerifier (NHat is from Pedersen)
// N1 = NProver
// C = NVerifier.Enc(c, rhoC)
// D = x • C + NVerifier.Enc(y, rho) == NVerifier.Enc(xc + y, rhoC^x rho)
// Y = NProver.Enc(y, rhoY)
// X = x•G
//
// Prover proves they know:
// x < 2**l
// y < 2** l'
//
// Ref: [CGGMP20] Figure 15 P.35
func NewAffineGroupCommitmentRange(group kyber.Group, NProver, NVerifier *paillier.PublicKey, pedersen *Pedersen, commitmentC, ciphertextD, ciphertextY *paillier.Ciphertext, commitmentX kyber.Point, x, y kyber.Scalar, rho, rhoY *paillier.Nonce) *AffineGroupCommitmentRange {
	N1 := NProver.N()
	N0 := NVerifier.N()
	NHat := pedersen.NHat()
	N0Squared := NVerifier.N2()

	alpha := arith.MustSample(TwoPowLEps)
	beta := arith.MustSample(TwoPowLPrimeEps)

	var gamma, m, delta, mu *big.Int
	bound := new(big.Int)
	gamma = arith.MustSample(bound.Mul(TwoPowLEps, NHat))
	delta = arith.MustSample(bound.Mul(TwoPowLEps, NHat))
	m = arith.MustSample(bound.Mul(TwoPowL, NHat))
	mu = arith.MustSample(bound.Mul(TwoPowL, NHat))

	// A, r
	AEnc, r := NVerifier.Enc(beta)
	A := new(big.Int)
	A.Exp(commitmentC.BigInt(), alpha, N0Squared)
	A.Mul(A, AEnc.BigInt())
	A.Mod(A, N0Squared)

	// Bx
	alphaScalar := group.Scalar().SetBytes(alpha.Bytes())
	Bx := group.Point().Mul(alphaScalar, nil)

	// By, rY
	By, rY := NProver.Enc(beta)

	// E
	E := pedersen.SPowXTPowY(alpha, gamma)

	// S
	S := pedersen.SPowXTPowY(arith.GetBigInt(x), m)

	// F
	F := pedersen.SPowXTPowY(beta, delta)

	// T
	T := pedersen.SPowXTPowY(arith.GetBigInt(y), mu)

	BxBin, _ := Bx.MarshalBinary()

	proof := &AffineGroupCommitmentRange{
		A:  A,
		By: By.BigInt(),
		E:  E,
		F:  F,
		S:  S,
		T:  T,
		Bx: BxBin,
	}

	e := proof.Challenge(NVerifier.N(), NProver.N(), commitmentC.BigInt(), ciphertextD.BigInt(), ciphertextY.BigInt(), commitmentX)

	proof.Z1 = new(big.Int).Mul(e, arith.GetBigInt(x))
	proof.Z1.Add(alpha, proof.Z1)

	proof.Z2 = new(big.Int).Mul(e, arith.GetBigInt(y))
	proof.Z2.Add(beta, proof.Z2)

	proof.Z3 = new(big.Int).Mul(e, m)
	proof.Z3.Add(gamma, proof.Z3)

	proof.Z4 = new(big.Int).Mul(e, mu)
	proof.Z4.Add(delta, proof.Z4)

	proof.W = new(big.Int).Exp(rho.BigInt(), e, N0)
	proof.W.Mul(proof.W, r.BigInt())
	proof.W.Mod(proof.W, N0)

	proof.Wy = new(big.Int).Exp(rhoY.BigInt(), e, N1)
	proof.Wy.Mul(proof.Wy, rY.BigInt())
	proof.Wy.Mod(proof.Wy, N1)

	return proof
}

func (proof *AffineGroupCommitmentRange) Challenge(N0, N1, C, D, Y *big.Int, X kyber.Point) *big.Int {
	// TODO Yeah, this breaks every thing, but in my defense it's hard to get right.
	return big.NewInt(42)
}

func (proof *AffineGroupCommitmentRange) Verify(group kyber.Group, NProver, NVerifier *paillier.PublicKey, pedersen *Pedersen, commitmentC, ciphertextD, ciphertextY *paillier.Ciphertext, commitmentX kyber.Point) error {
	// Check range
	if proof.Z1.Cmp(TwoPowLPrimeEps) == 1 {
		return fmt.Errorf("range z1: %w", ErrZKAffineGroupCommitmentRange)
	}

	if proof.Z2.Cmp(TwoPowLPrimeEps) == 1 {
		return fmt.Errorf("range z2: %w", ErrZKAffineGroupCommitmentRange)
	}

	e := proof.Challenge(NVerifier.N(), NProver.N(), commitmentC.BigInt(), ciphertextD.BigInt(), ciphertextY.BigInt(), commitmentX)

	NHat := pedersen.NHat()
	N0Squared := NVerifier.N2()
	N1Squared := NProver.N2()

	// 1)
	lhs := NVerifier.AffineWithNonce(commitmentC, proof.Z1, proof.Z2, proof.W).BigInt()

	rhs := new(big.Int).Exp(ciphertextD.BigInt(), e, N0Squared)
	rhs = rhs.Mul(rhs, proof.A)
	rhs = rhs.Mod(rhs, N0Squared)

	if rhs.Cmp(lhs) != 0 {
		return fmt.Errorf("check 1: %w", ErrZKAffineGroupCommitmentRange)
	}

	// 2)
	lhsG := group.Point().Mul(group.Scalar().SetBytes(proof.Z1.Bytes()), nil)
	rhsG := group.Point().Mul(group.Scalar().SetBytes(e.Bytes()), commitmentX)
	Bx := group.Point()
	err := Bx.UnmarshalBinary(proof.Bx)
	if err != nil {
		panic(err)
	}
	rhsG = rhsG.Add(rhsG, Bx)

	if !rhsG.Equal(lhsG) {
		return fmt.Errorf("check 2: %w", ErrZKAffineGroupCommitmentRange)
	}

	// 3)
	lhs = NProver.EncWithNonce(proof.Z2, proof.Wy).BigInt()
	rhs = rhs.Exp(ciphertextY.BigInt(), e, N1Squared)
	rhs.Mul(rhs, proof.By)
	rhs.Mod(rhs, N1Squared)

	if rhs.Cmp(lhs) != 0 {
		return fmt.Errorf("check 3: %w", ErrZKAffineGroupCommitmentRange)
	}

	// 4)
	lhs = pedersen.SPowXTPowY(proof.Z1, proof.Z3)

	rhs = rhs.Exp(proof.S, e, NHat)
	rhs.Mul(rhs, proof.E)
	rhs.Mod(rhs, NHat)

	if rhs.Cmp(lhs) != 0 {
		return fmt.Errorf("check 4: %w", ErrZKAffineGroupCommitmentRange)
	}

	// 5)
	lhs = pedersen.SPowXTPowY(proof.Z2, proof.Z4)

	rhs = rhs.Exp(proof.T, e, NHat)
	rhs.Mul(rhs, proof.F)
	rhs.Mod(rhs, NHat)

	if rhs.Cmp(lhs) != 0 {
		return fmt.Errorf("check 5: %w", ErrZKAffineGroupCommitmentRange)
	}

	return nil
}
