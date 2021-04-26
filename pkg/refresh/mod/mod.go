package zkmod

import (
	"fmt"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

var four = big.NewInt(4)

type (
	Public struct {
		// N = p*q
		N *big.Int
	}
	Private struct {
		// P, Q primes such that
		// P, Q = 3 mod 4
		P, Q *big.Int
		// Phi = ϕ(n) = (p-1)(q-1)
		Phi *big.Int
	}
)

func isQRmodPQ(y, p, q *big.Int) bool {
	return big.Jacobi(y, p) == 1 && big.Jacobi(y, q) == 1
}

// fourthRoot returns the 4th root modulo n, or a quadratic residue qr, given that:
//   - n = p•q
//   - phi = (p-1)(q-1)
//   - p,q = 3 (mod 4)  =>  n = 1 (mod 3)
//   - Jacobi(qr, p) == Jacobi(qr, q) == 1
//
// Set e to
//        ϕ + 4
//   e' = ------,   e = (e')²
//          8
//
// Then, (qrᵉ)⁴ = qr
func fourthRoot(qr, phi, n *big.Int) *big.Int {
	var e big.Int
	e.Add(phi, four)
	e.Mul(&e, &e)
	e.Rsh(&e, 6)
	e.Mod(&e, phi)
	return e.Exp(qr, &e, n)
}

// makeQuadraticResidue return a, b and y' such that:
//   y' = (-1)ᵃ • wᵇ • y
//  is a QR.
//
// With:
//   - n=pq is a blum integer
//   - w is a quadratic non residue in Zn
//   - y is an element that may or may not be a QR
func makeQuadraticResidue(y, w *big.Int, n, p, q *big.Int) (a, b bool, yPrime *big.Int) {
	yPrime = new(big.Int).Mod(y, n)

	if isQRmodPQ(y, p, q) {
		return
	}

	// multiply by -1
	yPrime.Neg(yPrime)
	yPrime.Mod(yPrime, n)
	a, b = true, false
	if isQRmodPQ(yPrime, p, q) {
		return
	}

	// multiply by -w
	yPrime.Mul(yPrime, w)
	yPrime.Mod(yPrime, n)
	a, b = true, true
	if isQRmodPQ(yPrime, p, q) {
		return
	}

	// multiply by w again
	yPrime.Neg(yPrime)
	yPrime.Mod(yPrime, n)
	a, b = false, true
	return
}

// Prove generates a proof that:
//   - n = pq
//   - p and q are odd primes
//   - p, q == 3 (mod n)
// With:
//  - W s.t. (w/N) = -1
//  - x = y' ^ {1/4}
//  - z = y^{N⁻¹ mod ϕ(N)}
//  - a, b s.t. y' = (-1)ᵃ wᵇ y
//  - R = [(xᵢ aᵢ, bᵢ), zᵢ] for i = 1, ..., m
func (public Public) Prove(hash *hash.Hash, private Private) (*pb.ZKMod, error) {
	var err error

	n, p, q, phi := public.N, private.P, private.Q, private.Phi
	w := sample.QNR(n)

	if err = hash.WriteInt(n, w); err != nil {
		return nil, fmt.Errorf("zkmod: prove: %w", err)
	}

	nInverse := new(big.Int).ModInverse(n, phi)

	Xs := make([]*pb.Int, params.StatParam)
	As := make([]bool, params.StatParam)
	Bs := make([]bool, params.StatParam)
	Zs := make([]*pb.Int, params.StatParam)

	var z big.Int
	y := new(big.Int)
	for i := 0; i < params.StatParam; i++ {
		if y, err = hash.ReadIntModN(n); err != nil {
			return nil, fmt.Errorf("zkmod: prove: %w", err)
		}

		// Z = y^{n⁻¹ (mod n)}
		z.Exp(y, nInverse, n)

		a, b, yPrime := makeQuadraticResidue(y, w, n, p, q)
		// X = (y')¹/4
		x := fourthRoot(yPrime, phi, n)

		Xs[i], As[i], Bs[i], Zs[i] = pb.NewInt(x), a, b, pb.NewInt(&z)
	}

	return &pb.ZKMod{
		W: pb.NewInt(w),
		X: Xs,
		A: As,
		B: Bs,
		Z: Zs,
	}, nil
}

func (public Public) Verify(hash *hash.Hash, proof *pb.ZKMod) bool {
	var err error
	n := public.N
	// check if n is odd or prime
	if n.Bit(0) == 0 || n.ProbablyPrime(20) {
		return false
	}

	if len(proof.X) != params.StatParam ||
		len(proof.A) != params.StatParam ||
		len(proof.B) != params.StatParam ||
		len(proof.Z) != params.StatParam {
		return false
	}

	w := proof.GetW().Unmarshal()
	if err = hash.WriteInt(n, w); err != nil {
		return false
	}

	var lhs, rhs big.Int
	y, z, x := new(big.Int), new(big.Int), new(big.Int)
	for i := 0; i < params.StatParam; i++ {
		// get yᵢ
		if y, err = hash.ReadIntModN(n); err != nil {
			return false
		}

		x = proof.X[i].Unmarshal()
		z = proof.Z[i].Unmarshal()

		{
			// lhs = zⁿ mod n
			lhs.Exp(z, n, n)
			if lhs.Cmp(y) != 0 {
				return false
			}
		}

		{
			// lhs = x⁴ (mod n)
			lhs.Exp(x, four, n)

			// rhs = y' = (-1)ᵃ • wᵇ • y
			rhs.Set(y)
			if proof.B[i] {
				rhs.Mul(&rhs, w)
			}
			if proof.A[i] {
				rhs.Neg(&rhs)
			}
			rhs.Mod(&rhs, n)

			if lhs.Cmp(&rhs) != 0 {
				return false
			}
		}
	}
	return true
}
