package polynomial

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

// NewPolynomialExponent generates a Exponent polynomial F(X) = [secret + a₁•X + … + aₜ•Xᵗ]•G,
// with Coefficient in G, and degree t.
func NewPolynomialExponent(polynomial *Polynomial) *Exponent {
	var p Exponent

	p.Coefficients = make([]curve.Point, len(polynomial.Coefficients))
	for i := range polynomial.Coefficients {
		p.Coefficients[i].ScalarBaseMult(&polynomial.Coefficients[i])
	}

	// This hack is needed so that we never send an encoded Identity point
	isConstant := polynomial.Constant().IsZero()
	if isConstant {
		p.IsConstant = true
		p.Coefficients = p.Coefficients[1:]
	}

	return &p
}

// Evaluate uses any one of the defined evaluation algorithms
func (p *Exponent) Evaluate(x *curve.Scalar) *curve.Point {
	return p.evaluateHorner(x)
}

// evaluateClassic evaluates a polynomial in a given variable index
// We do the classic method, where we compute all powers of x
func (p *Exponent) evaluateClassic(x *curve.Scalar) *curve.Point {
	var tmp curve.Point

	xPower := curve.NewScalarUInt32(1)
	result := curve.NewIdentityPoint()

	if p.IsConstant {
		// since we start at index 1 of the polynomial, x must be x and not 1
		xPower.Multiply(xPower, x)
	}

	for i := 0; i < len(p.Coefficients); i++ {
		// tmp = [xⁱ]Aᵢ
		tmp.ScalarMult(xPower, &p.Coefficients[i])
		// result += [xⁱ]Aᵢ
		result.Add(result, &tmp)

		// x = xⁱ⁺¹
		xPower.Multiply(xPower, x)
	}
	return result
}

// evaluateHorner evaluates a polynomial in a given variable index
func (p *Exponent) evaluateHorner(index *curve.Scalar) *curve.Point {
	result := curve.NewIdentityPoint()

	for i := len(p.Coefficients) - 1; i >= 0; i-- {
		// Bₙ₋₁ = [x]Bₙ  + Aₙ₋₁
		result.ScalarMult(index, result)
		result.Add(result, &p.Coefficients[i])
	}

	if p.IsConstant {
		// result is B₁
		// we want B₀ = [x]B₁ + A₀ = [x]B₁
		result.ScalarMult(index, result)
	}

	return result
}

// Degree returns the degree t of the polynomial
func (p *Exponent) Degree() int {
	if p.IsConstant {
		return len(p.Coefficients)
	} else {
		return len(p.Coefficients) - 1
	}
}

func (p *Exponent) add(q *Exponent) error {
	if len(p.Coefficients) != len(q.Coefficients) {
		return errors.New("q is not the same length as p")
	}

	if p.IsConstant != q.IsConstant {
		return errors.New("p and q differ in 'IsConstant'")
	}

	for i := 0; i < len(p.Coefficients); i++ {
		p.Coefficients[i].Add(&p.Coefficients[i], &q.Coefficients[i])
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
	q.Coefficients = make([]curve.Point, len(p.Coefficients))
	for i := 0; i < len(p.Coefficients); i++ {
		q.Coefficients[i].Set(&p.Coefficients[i])
	}
	q.IsConstant = p.IsConstant
	return &q
}

func (p *Exponent) Equal(other Exponent) bool {
	if len(p.Coefficients) != len(other.Coefficients) {
		return false
	}
	for i := 0; i < len(p.Coefficients); i++ {
		if !p.Coefficients[i].Equal(&other.Coefficients[i]) {
			return false
		}
	}
	return true
}

// Constant returns the constant coefficient of the polynomial 'in the exponent'
func (p *Exponent) Constant() *curve.Point {
	if p.IsConstant {
		return curve.NewIdentityPoint()
	} else {
		return &p.Coefficients[0]
	}
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (p *Exponent) WriteTo(w io.Writer) (int64, error) {
	// write the number of Coefficient
	_ = binary.Write(w, binary.BigEndian, uint32(p.Degree()))
	nAll := int64(4)

	if p.IsConstant {
		// write only zeros
		n0, _ := w.Write(make([]byte, params.BytesPoint))
		nAll += int64(n0)
	}

	// write all Coefficient
	for _, c := range p.Coefficients {
		n, err := c.WriteTo(w)
		nAll += n
		if err != nil {
			return nAll, err
		}
	}
	return nAll, nil
}
