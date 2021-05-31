package polynomial

import (
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
)

// Exponent represents a polynomial whose coefficients are points on an elliptic curve.
type Exponent struct {
	coefficients []*curve.Point
}

// NewPolynomialExponent generates a Exponent polynomial F(X) = [secret + a1*X + ... + at*X^t]•G,
// with coefficients in G, and degree t.
func NewPolynomialExponent(polynomial *Polynomial) *Exponent {
	var p Exponent

	p.coefficients = make([]*curve.Point, len(polynomial.coefficients))
	for i := range p.coefficients {
		p.coefficients[i] = curve.NewIdentityPoint().ScalarBaseMult(polynomial.coefficients[i])
	}

	return &p
}

// Evaluate uses any one of the defined evaluation algorithms
func (p *Exponent) Evaluate(index *curve.Scalar) *curve.Point {
	var result curve.Point
	// We chose evaluateVar since it is the fastest in CPU time, even though it uses more memory
	return p.evaluateHorner(index, &result)
}

// evaluateClassic evaluates a polynomial in a given variable index
// We do the classic method.
func (p *Exponent) evaluateClassic(index *curve.Scalar, result *curve.Point) *curve.Point {
	var tmp curve.Point

	x := curve.NewScalarBigInt(big.NewInt(1))

	result.Set(curve.NewIdentityPoint())
	for i := 0; i < len(p.coefficients); i++ {
		tmp.ScalarMult(x, p.coefficients[i])
		result.Add(result, &tmp)

		x.Multiply(x, index)
	}
	return result
}

// evaluateHorner evaluates a polynomial in a given variable index
// We create a list of all powers of index, and use VarTimeMultiScalarMult
// to speed things up.
func (p *Exponent) evaluateHorner(index *curve.Scalar, result *curve.Point) *curve.Point {
	result.Set(curve.NewIdentityPoint())

	for i := len(p.coefficients) - 1; i >= 0; i-- {
		// B_n-1 = [x]B_n  + A_n-1
		result.ScalarMult(index, result)
		result.Add(result, p.coefficients[i])
	}
	return result
}

func (p *Exponent) Degree() int {
	return len(p.coefficients) - 1
}

func (p *Exponent) add(q *Exponent) error {
	if len(p.coefficients) != len(q.coefficients) {
		return errors.New("q is not the same length as p")
	}

	for i := 0; i < len(p.coefficients); i++ {
		p.coefficients[i].Add(p.coefficients[i], q.coefficients[i])
	}

	return nil
}

// Sum creates a new Polynomial in the Exponent, by summing a slice of existing ones.
func Sum(polynomials []*Exponent) (*Exponent, error) {
	var err error

	// Create the new polynomial by copying the first one given
	summed := polynomials[0].Copy()

	// we assume all polynomials have the same degree as the first
	for j := 1; j < len(polynomials); j++ {
		err = summed.add(polynomials[j])
		if err != nil {
			return nil, err
		}
	}
	return summed, nil
}

func (p *Exponent) Copy() *Exponent {
	var q Exponent
	q.coefficients = make([]*curve.Point, len(p.coefficients))
	for i := 0; i < len(p.coefficients); i++ {
		q.coefficients[i] = curve.NewIdentityPoint().Set(p.coefficients[i])
	}
	return &q
}

func (p *Exponent) Equal(other Exponent) bool {
	if len(p.coefficients) != len(other.coefficients) {
		return false
	}
	for i := 0; i < len(p.coefficients); i++ {
		if !p.coefficients[i].Equal(other.coefficients[i]) {
			return false
		}
	}
	return true
}

// Constant returns the constant coefficient of the polynomial 'in the exponent'
func (p *Exponent) Constant() *curve.Point {
	return p.coefficients[0]
}

// AddConstant returns changes p and returns p(x) + constant
func (p *Exponent) AddConstant(c *curve.Point) *Exponent {
	q := p.Copy()
	q.coefficients[0].Add(q.coefficients[0], c)
	return q
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (p *Exponent) WriteTo(w io.Writer) (int64, error) {
	var n int64
	degree := uint32(len(p.coefficients))

	// write the number of coefficients
	err := binary.Write(w, binary.BigEndian, degree)
	if err != nil {
		return 0, err
	}
	nAll := int64(4)

	// write all coefficients
	for _, c := range p.coefficients {
		n, err = c.WriteTo(w)
		nAll += n
		if err != nil {
			return nAll, err
		}
	}
	return nAll, nil
}

func (p *Exponent) SetCoefficients(points []*curve.Point) *Exponent {
	p.coefficients = points
	return p
}

func (p *Exponent) Coefficients() []*curve.Point {
	return p.coefficients
}
