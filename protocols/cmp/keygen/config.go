package keygen

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	io "io"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/cmp-ecdsa/internal/proto"
	"github.com/taurusgroup/cmp-ecdsa/internal/writer"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

func newSecret(id party.ID, secretShareECDSA *curve.Scalar, secretPaillier *paillier.SecretKey) *Secret {
	return &Secret{
		ID:    id,
		ECDSA: secretShareECDSA,
		P:     &proto.NatMarshaller{Nat: secretPaillier.P()},
		Q:     &proto.NatMarshaller{Nat: secretPaillier.Q()},
	}
}

// PublicKey returns the group's public ECDSA key.
func (s Session) PublicKey() *ecdsa.PublicKey {
	return s.publicKey(s.PartyIDs()).ToPublicKey()
}

func (s Session) publicKey(partyIDs []party.ID) *curve.Point {
	sum := curve.NewIdentityPoint()
	tmp := curve.NewIdentityPoint()
	l := Lagrange(partyIDs)
	for j, partyJ := range s.Public {
		tmp.ScalarMult(l[j], partyJ.ECDSA)
		sum.Add(sum, tmp)
	}
	return sum
}

// Validate ensures that the data
func (s Session) Validate(secret *Secret) error {
	// verify number of parties w.r.t. threshold
	// want 0 ⩽ threshold ⩽ n-1
	if n := len(s.Public); n == 0 || s.Threshold < 0 || int(s.Threshold) > n-1 {
		return fmt.Errorf("session: threshold %d is invalid", s.Threshold)
	}

	for j, publicJ := range s.Public {
		// validate public
		if err := publicJ.validate(); err != nil {
			return fmt.Errorf("session: party %s: %w", j, err)
		}
	}

	if secret == nil {
		return nil
	}

	// verify our ID is present
	public := s.Public[secret.ID]
	if public == nil {
		return errors.New("session: no public data for secret")
	}

	// check secret
	if err := secret.validate(); err != nil {
		return fmt.Errorf("session: %w", err)
	}

	// is the public ECDSA key equal
	pk := curve.NewIdentityPoint().ScalarBaseMult(secret.ECDSA)
	if !pk.Equal(public.ECDSA) {
		return errors.New("session: ECDSA secret key share does not correspond to public share")
	}

	n := new(safenum.Nat).Mul(secret.P.Nat, secret.Q.Nat, -1).Big()
	// is our public key for paillier the same?
	if n.Cmp(public.N) != 0 {
		return errors.New("session: P•Q ≠ N")
	}

	return nil
}

func (s Session) PartyIDs() party.IDSlice {
	ids := make([]party.ID, 0, len(s.Public))
	for j := range s.Public {
		ids = append(ids, j)
	}
	return party.NewIDSlice(ids)
}

// validate returns an error if Public is invalid. Otherwise return nil.
func (p *Public) validate() error {
	if p == nil || p.ECDSA == nil || p.N == nil || p.S == nil || p.T == nil {
		return errors.New("public: one or more field is empty")
	}

	// ECDSA is not identity
	if p.ECDSA.IsIdentity() {
		return errors.New("public: ECDSA secret key share is zero")
	}

	// Paillier check
	if err := paillier.ValidateN(p.N); err != nil {
		return fmt.Errorf("public: %w", err)
	}

	// Pedersen check
	if err := pedersen.ValidateParameters(p.N, p.S, p.T); err != nil {
		return fmt.Errorf("public: %w", err)
	}

	return nil
}

// validate returns an error if Secret is invalid. Otherwise return nil.
func (s *Secret) validate() error {
	if s == nil || s.ECDSA == nil || s.P == nil || s.Q == nil {
		return errors.New("secret: one or more field is empty")
	}

	// ECDSA is not identity
	if s.ECDSA.IsZero() {
		return errors.New("public: ECDSA public key share is identity")
	}

	// Paillier check
	if err := paillier.ValidatePrime(s.P.Nat); err != nil {
		return fmt.Errorf("public: prime p: %w", err)
	}
	if err := paillier.ValidatePrime(s.Q.Nat); err != nil {
		return fmt.Errorf("public: prime q: %w", err)
	}

	return nil
}

func (s *Secret) Paillier() *paillier.SecretKey {
	return paillier.NewSecretKeyFromPrimes(s.P.Nat, s.Q.Nat)
}

// Lagrange returns the Lagrange coefficient
//
// We iterate over all points in the set.
// To get the coefficients over a smaller set,
// you should first get a smaller subset.
//
// The following formulas are taken from
// https://en.wikipedia.org/wiki/Lagrange_polynomial
//			        x₀ … xₖ
// lⱼ(0) =	---------------------------
//			xⱼ⋅(x₀ - xⱼ) … (xₖ - xⱼ)
func Lagrange(partyIDs []party.ID) map[party.ID]*curve.Scalar {
	// product = x₀ * … * x_k
	product := curve.NewScalarUInt32(1)
	scalars := make(map[party.ID]*curve.Scalar, len(partyIDs))
	for _, id := range partyIDs {
		xi := id.Scalar()
		scalars[id] = xi
		product.Multiply(product, xi)
	}

	coefficients := make(map[party.ID]*curve.Scalar, len(partyIDs))
	tmp := curve.NewScalar()
	for _, j := range partyIDs {
		xJ := scalars[j]
		// lⱼ = -xⱼ
		lJ := curve.NewScalar().Negate(xJ)

		for _, i := range partyIDs {
			if i == j {
				continue
			}
			// tmp = xⱼ - xᵢ
			xI := scalars[i]
			tmp.Subtract(xJ, xI)
			// lⱼ *= xⱼ - xᵢ
			lJ.Multiply(lJ, tmp)
		}

		lJ.Invert(lJ)
		lJ.Multiply(lJ, product)
		coefficients[j] = lJ
	}
	return coefficients
}

// WriteTo implements io.WriterTo interface.
func (s Session) WriteTo(w io.Writer) (total int64, err error) {
	var n int64

	// write t
	n, err = writer.WriteWithDomain(w, Threshold(s.Threshold))
	total += n
	if err != nil {
		return
	}

	// write rid
	n, err = writer.WriteWithDomain(w, s.RID)
	total += n
	if err != nil {
		return
	}

	for _, j := range s.PartyIDs() {
		// write Xⱼ
		n, err = writer.WriteWithDomain(w, s.Public[j])
		total += n
		if err != nil {
			return
		}
	}

	return
}

// Domain implements writer.WriterToWithDomain.
func (s Session) Domain() string {
	return "CMP Session"
}

// Domain implements writer.WriterToWithDomain.
func (Public) Domain() string {
	return "Public Data"
}

// WriteTo implements io.WriterTo interface.
func (p Public) WriteTo(w io.Writer) (total int64, err error) {
	var n int64
	buf := make([]byte, params.BytesIntModN)

	// write ECDSA
	n, err = writer.WriteWithDomain(w, p.ECDSA)
	total += n
	if err != nil {
		return
	}

	// write N
	p.N.FillBytes(buf)
	n, err = writer.WriteWithDomain(w, &writer.BytesWithDomain{
		TheDomain: "N",
		Bytes:     buf,
	})
	total += n
	if err != nil {
		return
	}
	// write S
	p.S.FillBytes(buf)
	n, err = writer.WriteWithDomain(w, &writer.BytesWithDomain{
		TheDomain: "S",
		Bytes:     buf,
	})
	total += n
	if err != nil {
		return
	}
	// write T
	p.T.FillBytes(buf)
	n, err = writer.WriteWithDomain(w, &writer.BytesWithDomain{
		TheDomain: "T",
		Bytes:     buf,
	})
	total += n
	if err != nil {
		return
	}
	return
}
