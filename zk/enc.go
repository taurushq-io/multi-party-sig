package zk

import "C"
import (
	"errors"
	"fmt"
	"github.com/taurusgroup/cmp-ecdsa/arith"
	"github.com/taurusgroup/cmp-ecdsa/paillier"
	"math/big"
)

type EncryptionInRangeProof struct {
	S, A, C *big.Int

	Z1, Z2, Z3 *big.Int
}

var ErrZKEncryptionInRange = errors.New("zk: enc: verification failed")

// NewEncryptionInRange computes a Zero Knowledge proof of the following statement:
//
// Public:
// N0 = NProver
// N1 = NHat = NVerifier (NHat is from Pedersen)
// K = NProver.Enc(k, rho)
//
// Prover proves they know:
// k < 2**l
//
// Ref: [CGGMP20] Figure 14 P.33
func NewEncryptionInRange(NProver, NVerifier *paillier.PublicKey, pedersen *Pedersen, ciphertext *paillier.Ciphertext, plaintext *big.Int, nonce *paillier.Nonce) *EncryptionInRangeProof {
	NHat := pedersen.NHat()
	alpha := arith.MustSample(TwoPowLEps)

	bound := new(big.Int)
	mu := arith.MustSample(bound.Mul(TwoPowL, NHat))
	gamma := arith.MustSample(bound.Mul(TwoPowLEps, NHat))

	proof := &EncryptionInRangeProof{}

	// S
	proof.S = pedersen.SPowXTPowY(plaintext, mu)

	// A
	A, r := NProver.Enc(alpha)
	proof.A = A.BigInt()

	// C
	proof.C = pedersen.SPowXTPowY(alpha, gamma)

	e := proof.Challenge(NProver, NVerifier, ciphertext)

	proof.Z1 = new(big.Int).Mul(e, plaintext) // ek
	proof.Z1 = proof.Z1.Add(proof.Z1, alpha)  // Z1 = a + ek

	proof.Z2 = new(big.Int).Exp(nonce.BigInt(), e, NProver.N()) // Z2 = nonce ^e
	proof.Z2.Mul(proof.Z2, r.BigInt())                          // Z2 = r * rho^e
	proof.Z2.Mod(proof.Z2, NProver.N())

	proof.Z3 = new(big.Int).Mul(e, mu)       //emu
	proof.Z3 = proof.Z3.Add(proof.Z3, gamma) // Z1 = gamma + e mu

	return proof
}

func (proof *EncryptionInRangeProof) Challenge(NProver, NVerifier *paillier.PublicKey, ciphertext *paillier.Ciphertext) *big.Int {
	// TODO Yeah, this breaks every thing, but in my defense it's hard to get right.
	return big.NewInt(42)
}

// n0=ni prover, nhat=njverif
func (proof *EncryptionInRangeProof) Verify(NProver, NVerifier *paillier.PublicKey, pedersen *Pedersen, ciphertext *paillier.Ciphertext) error {
	N0Squared := NProver.N2()
	NHat := pedersen.NHat()

	// Check range
	if proof.Z1.Cmp(TwoPowLEps) == 1 {
		return fmt.Errorf("range z1: %w", ErrZKEncryptionInRange)
	}

	e := proof.Challenge(NProver, NVerifier, ciphertext)

	// Check enc
	lhs := NProver.EncWithNonce(proof.Z1, proof.Z2).BigInt()

	rhs := new(big.Int).Exp(ciphertext.BigInt(), e, N0Squared)
	rhs.Mul(rhs, proof.A)
	rhs.Mod(rhs, N0Squared)

	if rhs.Cmp(lhs) != 0 {
		return fmt.Errorf("check 1: %w", ErrZKEncryptionInRange)
	}

	// Check Pedersen
	lhs = pedersen.SPowXTPowY(proof.Z1, proof.Z3)

	rhs = rhs.Exp(proof.S, e, NHat)
	rhs.Mul(rhs, proof.C)
	rhs.Mod(rhs, NHat)

	if rhs.Cmp(lhs) != 0 {
		return fmt.Errorf("check 2: %w", ErrZKEncryptionInRange)
	}

	return nil
}
