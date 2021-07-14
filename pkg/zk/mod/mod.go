package zkmod

import (
	"crypto/rand"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

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
//   - p,q = 3 (mod 4)  =>  n = 1 (mod 4)
//   - Jacobi(qr, p) == Jacobi(qr, q) == 1
//
// Set e to
//        ϕ + 4
//   e' = ------,   e = (e')²
//          8
//
// Then, (qrᵉ)⁴ = qr
func fourthRoot(qr, phi, n *big.Int) *big.Int {
	var result big.Int
	e := big.NewInt(4)
	e.Add(phi, e)
	e.Mul(e, e)
	e.Rsh(e, 6)
	e.Mod(e, phi)
	return result.Exp(qr, e, n)
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

func (p *Proof) IsValid(public Public) bool {
	if len(*p.X) != params.StatParam ||
		len(p.A) != params.StatParam ||
		len(p.B) != params.StatParam ||
		len(*p.Z) != params.StatParam {
		return false
	}

	// W cannot be 0
	if p.W.Cmp(big.NewInt(0)) != 1 {
		return false
	}
	// W < N
	if p.W.Cmp(public.N) != -1 {
		return false
	}

	if !arith.IsValidModN(public.N, *p.Z...) {
		return false
	}
	if !arith.IsValidModN(public.N, *p.X...) {
		return false
	}

	return true
}

// NewProof generates a proof that:
//   - n = pq
//   - p and q are odd primes
//   - p, q == 3 (mod n)
// With:
//  - W s.t. (w/N) = -1
//  - x = y' ^ {1/4}
//  - z = y^{N⁻¹ mod ϕ(N)}
//  - a, b s.t. y' = (-1)ᵃ wᵇ y
//  - R = [(xᵢ aᵢ, bᵢ), zᵢ] for i = 1, …, m
func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	n, p, q, phi := public.N, private.P, private.Q, private.Phi
	w := sample.QNR(rand.Reader, n)

	nInverse := new(big.Int).ModInverse(n, phi)

	Xs := make([]*big.Int, params.StatParam)
	As := make([]bool, params.StatParam)
	Bs := make([]bool, params.StatParam)
	Zs := make([]*big.Int, params.StatParam)

	ys := challenge(hash, n, w)

	for i := 0; i < params.StatParam; i++ {
		y := ys[i]

		// Z = y^{n⁻¹ (mod n)}
		z := new(big.Int).Exp(y, nInverse, n)

		a, b, yPrime := makeQuadraticResidue(y, w, n, p, q)
		// X = (y')¹/4
		x := fourthRoot(yPrime, phi, n)

		Xs[i], As[i], Bs[i], Zs[i] = x, a, b, z
	}

	return &Proof{
		W: w,
		X: &Xs,
		A: As,
		B: Bs,
		Z: &Zs,
	}
}

func (p *Proof) Verify(hash *hash.Hash, public Public) bool {
	n := public.N
	// check if n is odd and prime
	if n.Bit(0) == 0 || n.ProbablyPrime(20) {
		return false
	}

	if !p.IsValid(public) {
		return false
	}

	if big.Jacobi(p.W, n) != -1 || p.W.Cmp(n) != -1 {
		return false
	}

	// get [yᵢ] <- ℤₙ
	ys := challenge(hash, n, p.W)

	var lhs, rhs big.Int
	z, x := new(big.Int), new(big.Int)
	four := big.NewInt(4)
	for i := 0; i < params.StatParam; i++ {
		// get yᵢ
		y := ys[i]

		x = (*p.X)[i]
		z = (*p.Z)[i]

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
			if p.B[i] {
				rhs.Mul(&rhs, p.W)
			}
			if p.A[i] {
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

func challenge(h *hash.Hash, n, w *big.Int) []*big.Int {
	_, _ = h.WriteAny(n, w)
	intBuffer := make([]byte, params.BytesIntModN)
	out := make([]*big.Int, params.StatParam)
	for i := range out {
		var r big.Int
		_, _ = h.ReadBytes(intBuffer)
		r.SetBytes(intBuffer)
		r.Mod(&r, n)
		out[i] = &r
	}

	return out
}
