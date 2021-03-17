package zkmod

import (
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/sample"
	"golang.org/x/crypto/blake2b"
)

var four = big.NewInt(4)

const domain = "CMP-MOD"

type Commitment struct {
	// W s.t. (w/N) = -1
	W *big.Int
}

type ResponseSub struct {
	X, Z *big.Int
	a, b bool
}

type Response struct {
	R [params.StatParam]ResponseSub
}

type Proof struct {
	*Commitment
	*Response
}

func (commitment *Commitment) Challenge(N, w *big.Int) [params.StatParam]big.Int {
	var challenges [params.StatParam]big.Int

	modulusSize := 2 * params.PaillierBits / 8
	size := params.StatParam * modulusSize

	key := make([]byte, 32)
	copy(key, domain)

	xof, err := blake2b.NewXOF(uint32(size), key)
	if err != nil {
		panic(err)
	}
	_, err = xof.Write(N.Bytes())
	if err != nil {
		panic(err)
	}
	_, err = xof.Write(w.Bytes())
	if err != nil {
		panic(err)
	}

	buffer := make([]byte, modulusSize)
	for i := 0; i < params.StatParam; i++ {
		_, err = xof.Read(buffer)
		if err != nil {
			panic(err)
		}
		challenges[i].SetBytes(buffer)
		challenges[i].Mod(&challenges[i], N)
	}

	return challenges
}

func findTwoSqrts(y, p *big.Int) (*big.Int, *big.Int) {
	var x1, x2 big.Int
	x1.ModSqrt(y, p)
	x2.Sub(p, &x1)
	return &x1, &x2
}

func crt(modP, modQ, p, q, n *big.Int) *big.Int {
	var pInv, qInv, result big.Int
	pInv.ModInverse(p, q)
	pInv.Mul(&pInv, p)
	pInv.Mul(&pInv, modP)

	qInv.ModInverse(q, p)
	qInv.Mul(&qInv, q)
	qInv.Mul(&qInv, modQ)

	result.Add(&pInv, &qInv)
	result.Mod(&result, n)
	return &result
}

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
//        phi + 4
//   e' = -------,   e = (e')^2
//           8
//
// Then, (qr^e)^4 = qr
func fourthRoot(qr, phi, n *big.Int) *big.Int {
	var e big.Int
	e.Add(phi, four)
	e.Mul(&e, &e)
	e.Rsh(&e, 6)
	e.Mod(&e, phi)
	return e.Exp(qr, &e, n)
}

// makeQuadraticResidue return a, b and y' such that:
//   y' = (-1)^a • w^b • y
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

// NewProof generates a proof that:
//   - n = pq
//   - p and q are odd primes
//   - p, q == 3 (mod n)
func NewProof(n, p, q, phi *big.Int) *Proof {
	w := sample.QNR(n)
	c := Commitment{W: w}
	ys := c.Challenge(n, w)

	response := Response{}

	var nInverse big.Int
	var yPrime *big.Int
	nInverse.ModInverse(n, phi)

	for i := 0; i < params.StatParam; i++ {
		y := &ys[i]
		r := &response.R[i]

		// Z = y^{n^-1} (mod n)
		r.Z = new(big.Int).Exp(y, &nInverse, n)

		r.a, r.b, yPrime = makeQuadraticResidue(y, w, n, p, q)
		// X = (y')^1/4
		r.X = fourthRoot(yPrime, phi, n)
	}

	return &Proof{
		Commitment: &c,
		Response:   &response,
	}
}

func (proof *Proof) Verify(n *big.Int) bool {
	if n.Bit(0) == 0 {
		return false
	}

	if n.ProbablyPrime(20) {
		return false
	}

	ys := proof.Challenge(n, proof.W)

	var lhs, rhs big.Int
	for i := 0; i < params.StatParam; i++ {
		r := &proof.R[i]
		y := &ys[i]

		{
			// lhs = z^n mod n
			lhs.Exp(r.Z, n, n)
			if lhs.Cmp(y) != 0 {
				return false
			}
		}

		{
			// lhs = x^4 (mod n)
			lhs.Exp(r.X, four, n)

			// rhs = y' = (-1)^a • w^b • y
			rhs.Set(y)
			if r.b {
				rhs.Mul(&rhs, proof.W)
			}
			if r.a {
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
