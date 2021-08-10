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

type Public struct {
	// N = p*q
	N *safenum.Modulus
}

type Private struct {
	// P, Q primes such that
	// P, Q ≡ 3 mod 4
	P, Q *safenum.Nat
	// Phi = ϕ(n) = (p-1)(q-1)
	Phi *safenum.Nat
}

type Response struct {
	// A, B s.t. y' = (-1)ᵃ wᵇ y
	A, B bool
	// X = y' ^ {1/4}
	X *safenum.Nat
	// Z = y^{N⁻¹ mod ϕ(N)}
	Z *safenum.Nat
}
type Proof struct {
	W         *safenum.Nat
	Responses [params.StatParam]Response
}

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
	if p == nil {
		return false
	}
	if big.Jacobi(p.W.Big(), public.N.Big()) != -1 {
		return false
	}

	if !arith.IsValidNatModN(public.N, p.W) {
		return false
	}
	for _, r := range p.Responses {
		if !arith.IsValidNatModN(public.N, r.X, r.Z) {
			return false
		}
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
	nNat := n.Nat()
	// W can be leaked so no need to make this sampling return a nat.
	w := sample.QNR(rand.Reader, n)

	nInverse := new(safenum.Nat).ModInverse(nNat, phiMod)

	var rs [params.StatParam]Response

	ys, _ := challenge(hash, n, w)

	pl.Parallelize(params.StatParam, func(i int) interface{} {
		y := ys[i]

		// Z = y^{n⁻¹ (mod n)}
		z := new(safenum.Nat).Exp(y, nInverse, n)

		a, b, yPrime := makeQuadraticResidue(y, w, pHalf, qHalf, n, pMod, qMod)
		// X = (y')¹/4
		x := fourthRoot(yPrime, phi, n)

		rs[i] = Response{
			A: a,
			B: b,
			X: x,
			Z: z,
		}

		return nil
	})

	return &Proof{
		W:         w,
		Responses: rs,
	}
}

func (p *Proof) Verify(pl *pool.Pool, hash *hash.Hash, public Public) bool {
	n := public.N.Big()
	nMod := public.N
	// check if n is odd and prime
	if n.Bit(0) == 0 || n.ProbablyPrime(20) {
		return false
	}

	w := p.W.Big()
	if big.Jacobi(w, n) != -1 {
		return false
	}

	if !arith.IsValidBigModN(n, w) {
		return false
	}

	// get [yᵢ] <- ℤₙ
	ys, err := challenge(hash, nMod, p.W)
	if err != nil {
		return false
	}
	four := big.NewInt(4)
	verifications := pl.Parallelize(params.StatParam, func(i int) interface{} {
		r := p.Responses[i]
		var lhs, rhs big.Int
		// get yᵢ
		y := ys[i].Big()

		x := r.X.Big()
		z := r.Z.Big()

		// check co-primality
		if !arith.IsValidBigModN(n, x, z) {
			return false
		}

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
			if r.B {
				rhs.Mul(&rhs, w)
			}
			if r.A {
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

func challenge(hash *hash.Hash, n *safenum.Modulus, w *safenum.Nat) (es []*safenum.Nat, err error) {
	err = hash.WriteAny(n, w)
	es = make([]*safenum.Nat, params.StatParam)
	for i := range es {
		es[i] = sample.ModN(hash.Digest(), n)
	}
	return
}
