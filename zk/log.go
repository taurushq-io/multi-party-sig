package zk

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/arith"
	"github.com/taurusgroup/cmp-ecdsa/paillier"

	"math/big"

	"go.dedis.ch/kyber/v3"
)

type Log struct {
	S, A, D *big.Int
	Y       []byte

	Z1, Z2, Z3 *big.Int
}

var ErrZKLog = errors.New("zk: log: verification failed")

// NewLog computes a Zero Knowledge proof of the following statement:
//
// Public:
// N0 = NProver
// N1 = NHat = NVerifier (NHat is from Pedersen)
// C = NProver.Enc(c, rhoC)
// X = x•G
//
// Prover proves they know:
// x < 2**l
//
// Ref: [CGGMP20] Figure 25 P.63
func NewLog(group kyber.Group, NProver, NVerifier *paillier.PublicKey, pedersen *Pedersen, commitmentC *paillier.Ciphertext, commitmentX, pointG kyber.Point, x kyber.Scalar, rho *paillier.Nonce) *Log {
	NHat := pedersen.NHat()

	alpha := arith.MustSample(TwoPowLEps)

	var gamma, mu *big.Int
	bound := new(big.Int)
	mu = arith.MustSample(bound.Mul(TwoPowL, NHat))
	gamma = arith.MustSample(bound.Mul(TwoPowLEps, NHat))

	//D
	D := pedersen.SPowXTPowY(alpha, gamma)

	//A
	A, r := NProver.Enc(alpha)

	// Y
	Y := group.Point().Mul(group.Scalar().SetBytes(alpha.Bytes()), pointG)

	// S
	S := pedersen.SPowXTPowY(arith.GetBigInt(x), mu)

	YBin, _ := Y.MarshalBinary()
	proof := &Log{
		S: S,
		A: A.BigInt(),
		D: D,
		Y: YBin,
	}

	e := proof.Challenge(NProver, NVerifier, commitmentC, commitmentX, group.Point().Base())

	proof.Z1 = new(big.Int).Mul(e, arith.GetBigInt(x))
	proof.Z1.Add(proof.Z1, alpha)

	proof.Z2 = new(big.Int).Exp(rho.BigInt(), e, NProver.N())
	proof.Z2.Mul(proof.Z2, r.BigInt())
	proof.Z2.Mod(proof.Z2, NProver.N())

	proof.Z3 = new(big.Int).Mul(e, mu)
	proof.Z3.Add(proof.Z3, gamma)

	return proof
}

func (proof *Log) Challenge(NProver, NVerifier *paillier.PublicKey, commitmentC *paillier.Ciphertext, commitmentX, pointG kyber.Point) *big.Int {
	// TODO Yeah, this breaks every thing, but in my defense it's hard to get right.
	return big.NewInt(42)
}

func (proof *Log) Verify(group kyber.Group, NProver, NVerifier *paillier.PublicKey, pedersen *Pedersen, commitmentC *paillier.Ciphertext, commitmentX, pointG kyber.Point) error {
	N0Squared := NProver.N2()
	NHat := pedersen.NHat()

	// Check range
	if proof.Z1.Cmp(TwoPowLEps) == 1 {
		return fmt.Errorf("range z1: %w", ErrZKLog)
	}

	e := proof.Challenge(NProver, NVerifier, commitmentC, commitmentX, group.Point().Base())

	// 1)
	lhs := NProver.EncWithNonce(proof.Z1, proof.Z2).BigInt()

	rhs := new(big.Int).Exp(commitmentC.BigInt(), e, N0Squared)
	rhs.Mul(rhs, proof.A)
	rhs.Mod(rhs, N0Squared)
	if lhs.Cmp(rhs) != 0 {
		return fmt.Errorf("check 1: %w", ErrZKLog)
	}

	// 2)
	lhsG := group.Point().Mul(group.Scalar().SetBytes(proof.Z1.Bytes()), pointG)

	Y := group.Point()
	err := Y.UnmarshalBinary(proof.Y)
	if err != nil {
		return fmt.Errorf("check 2: %w", err)
	}

	rhsG := group.Point().Mul(group.Scalar().SetBytes(e.Bytes()), commitmentX)
	rhsG = rhsG.Add(rhsG, Y)
	if !lhsG.Equal(rhsG) {
		return fmt.Errorf("check 2: %w", ErrZKLog)
	}

	// 3)
	lhs = pedersen.SPowXTPowY(proof.Z1, proof.Z3)

	rhs = rhs.Exp(proof.S, e, NHat)
	rhs.Mul(rhs, proof.D)
	rhs.Mod(rhs, NHat)

	if lhs.Cmp(rhs) != 0 {
		return fmt.Errorf("check 3: %w", ErrZKLog)
	}

	return nil
}
