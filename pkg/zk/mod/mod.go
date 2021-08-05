package zkmod

import (
	"crypto/rand"
	"math/big"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

type (
	Public struct {
		// N = p*q
		N *big.Int
	}
	Private struct {
		// P, Q primes such that
		// P, Q = 3 mod 4
		P, Q *safenum.Nat
		// Phi = ϕ(n) = (p-1)(q-1)
		Phi *safenum.Nat
	}
)

var oneNat = new(safenum.Nat).SetUint64(1).Resize(1)

// isQRModPQ checks that y is a quadratic residue mod both p and q.
//
// p and q should be prime numbers.
//
// pHalf should be (p - 1) / 2
//
// qHalf should be (q - 1) / 2.
func isQRmodPQ(y, pHalf, qHalf *safenum.Nat, p, q *safenum.Modulus) safenum.Choice {
	test := new(safenum.Nat)

	test.Exp(y, pHalf, p)
	pOk := test.Eq(oneNat)

	test.Exp(y, qHalf, q)
	qOk := test.Eq(oneNat)

	return pOk & qOk
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
// Then, (qrᵉ)⁴ = qr.
func fourthRoot(qr, phi *safenum.Nat, n *safenum.Modulus) *safenum.Nat {
	e := new(safenum.Nat).SetUint64(4)
	e.Add(e, phi, -1)
	e.Rsh(e, 3, -1)
	e.ModMul(e, e, safenum.ModulusFromNat(phi))
	return new(safenum.Nat).Exp(qr, e, n)
}

// makeQuadraticResidue return a, b and y' such that:
//   y' = (-1)ᵃ • wᵇ • y
//  is a QR.
//
// With:
//   - n=pq is a blum integer
//   - w is a quadratic non residue in Zn
//   - y is an element that may or may not be a QR
//   - pHalf = (p - 1) / 2
//   - qHalf = (p - 1) / 2
//
// Leaking the return values is fine, but not the input values related to the factorization of N.
func makeQuadraticResidue(y, w, pHalf, qHalf *safenum.Nat, n, p, q *safenum.Modulus) (a, b bool, out *safenum.Nat) {
	out = new(safenum.Nat).Mod(y, n)

	if isQRmodPQ(out, pHalf, qHalf, p, q) == 1 {
		return
	}

	// multiply by -1
	out.ModNeg(out, n)
	a, b = true, false
	if isQRmodPQ(out, pHalf, qHalf, p, q) == 1 {
		return
	}

	// multiply by w again
	out.ModMul(out, w, n)
	a, b = true, true
	if isQRmodPQ(out, pHalf, qHalf, p, q) == 1 {
		return
	}

	// multiply by -1 again
	out.ModNeg(out, n)
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
func NewProof(pl *pool.Pool, hash *hash.Hash, public Public, private Private) *Proof {
	n, p, q, phi := public.N, private.P, private.Q, private.Phi
	pHalf := new(safenum.Nat).Sub(p, oneNat, -1)
	pHalf.Rsh(pHalf, 1, -1)
	pMod := safenum.ModulusFromNat(p)
	qHalf := new(safenum.Nat).Sub(q, oneNat, -1)
	qHalf.Rsh(qHalf, 1, -1)
	qMod := safenum.ModulusFromNat(q)
	phiMod := safenum.ModulusFromNat(phi)
	nNat := new(safenum.Nat).SetBig(n, n.BitLen())
	nMod := safenum.ModulusFromNat(nNat)
	// W can be leaked so no need to make this sampling return a nat.
	w := sample.QNR(rand.Reader, n)
	wNat := new(safenum.Nat).SetBig(w, w.BitLen())

	nInverse := new(safenum.Nat).ModInverse(nNat, phiMod)

	Xs := make([]*big.Int, params.StatParam)
	As := make([]bool, params.StatParam)
	Bs := make([]bool, params.StatParam)
	Zs := make([]*big.Int, params.StatParam)

	ys := challenge(hash, n, w)

	pl.Parallelize(params.StatParam, func(i int) interface{} {
		y := new(safenum.Nat).SetBig(ys[i], ys[i].BitLen())

		// Z = y^{n⁻¹ (mod n)}
		z := new(safenum.Nat).Exp(y, nInverse, nMod)

		a, b, yPrime := makeQuadraticResidue(y, wNat, pHalf, qHalf, nMod, pMod, qMod)
		// X = (y')¹/4
		x := fourthRoot(yPrime, phi, nMod)

		Xs[i], As[i], Bs[i], Zs[i] = x.Big(), a, b, z.Big()

		return nil
	})

	return &Proof{
		W: w,
		X: &Xs,
		A: As,
		B: Bs,
		Z: &Zs,
	}
}

func (p *Proof) Verify(pl *pool.Pool, hash *hash.Hash, public Public) bool {
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

	four := big.NewInt(4)
	verifications := pl.Parallelize(params.StatParam, func(i int) interface{} {
		var lhs, rhs big.Int
		// get yᵢ
		y := ys[i]

		x := (*p.X)[i]
		z := (*p.Z)[i]

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

		return true
	})
	for i := 0; i < len(verifications); i++ {
		if !verifications[i].(bool) {
			return false
		}
	}
	return true
}

func challenge(hash *hash.Hash, n, w *big.Int) []*big.Int {
	_ = hash.WriteAny(n, w)
	out := make([]*big.Int, params.StatParam)
	nMod := safenum.ModulusFromNat(new(safenum.Nat).SetBig(n, n.BitLen()))
	for i := range out {
		out[i] = sample.ModN(hash.Digest(), nMod).Big()
	}

	return out
}
