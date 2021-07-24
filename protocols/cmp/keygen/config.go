package keygen

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/cmp-ecdsa/internal/writer"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

// PublicKey returns the group's public ECDSA key.
func (c Config) PublicKey() *ecdsa.PublicKey {
	sum := curve.NewIdentityPoint()
	tmp := curve.NewIdentityPoint()
	partyIDs := make([]party.ID, 0, len(c.Public))
	for j := range c.Public {
		partyIDs = append(partyIDs, j)
	}
	l := polynomial.Lagrange(partyIDs)
	for j, partyJ := range c.Public {
		tmp.ScalarMult(l[j], partyJ.ECDSA)
		sum.Add(sum, tmp)
	}
	return sum.ToPublicKey()
}

// Validate ensures that the data is consistent. In particular it verifies:
// - 0 ⩽ threshold ⩽ n-1
// - all public data is present and valid
// - the secret corresponds to the data from an included party.
func (c Config) Validate() error {
	// verify number of parties w.r.t. threshold
	// want 0 ⩽ threshold ⩽ n-1
	if n := len(c.Public); n == 0 || c.Threshold < 0 || int(c.Threshold) > n-1 {
		return fmt.Errorf("config: threshold %d is invalid", c.Threshold)
	}

	// check secret key is present
	if c.Secret == nil {
		return errors.New("config: no secret data present")
	}

	for j, publicJ := range c.Public {
		// validate public
		if err := publicJ.validate(); err != nil {
			return fmt.Errorf("config: party %s: %w", j, err)
		}
	}

	// verify our ID is present
	public := c.Public[c.ID]
	if public == nil {
		return errors.New("config: no public data for secret")
	}

	// check secret
	if err := c.Secret.validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// is the public ECDSA key equal
	pk := curve.NewIdentityPoint().ScalarBaseMult(c.Secret.ECDSA)
	if !pk.Equal(public.ECDSA) {
		return errors.New("config: ECDSA secret key share does not correspond to public share")
	}

	n := new(safenum.Nat).Mul(c.Secret.P.Nat, c.Secret.Q.Nat, -1).Big()
	// is our public key for paillier the same?
	if n.Cmp(public.N) != 0 {
		return errors.New("config: P•Q ≠ N")
	}

	return nil
}

// PartyIDs returns a sorted slice of party IDs.
func (c Config) PartyIDs() party.IDSlice {
	ids := make([]party.ID, 0, len(c.Public))
	for j := range c.Public {
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
		return errors.New("public: ECDSA public key share is identity")
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
		return errors.New("public: ECDSA secret key share is zero")
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

// Paillier returns the secret Paillier key associated to this party.
func (s *Secret) Paillier() *paillier.SecretKey {
	return paillier.NewSecretKeyFromPrimes(s.P.Nat, s.Q.Nat)
}

// WriteTo implements io.WriterTo interface.
func (c Config) WriteTo(w io.Writer) (total int64, err error) {
	var n int64

	// write t
	n, err = writer.WriteWithDomain(w, Threshold(c.Threshold))
	total += n
	if err != nil {
		return
	}

	// write rid
	n, err = writer.WriteWithDomain(w, c.RID)
	total += n
	if err != nil {
		return
	}

	for _, j := range c.PartyIDs() {
		// write Xⱼ
		n, err = writer.WriteWithDomain(w, c.Public[j])
		total += n
		if err != nil {
			return
		}
	}

	return
}

// Domain implements writer.WriterToWithDomain.
func (c Config) Domain() string {
	return "CMP Config"
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

// CanSign returns true if the given _sorted_ list of signers is
// a valid subset of the original parties of size > t,
// and includes self.
func (c *Config) CanSign(signers party.IDSlice) bool {
	if !signers.Valid() {
		return false
	}
	// check that the signers are a subset of the original parties,
	// that it includes self, and that the size is > t.
	for _, j := range signers {
		if _, ok := c.Public[j]; !ok {
			return false
		}
	}
	if !signers.Contains(c.ID) {
		return false
	}
	if len(signers) <= int(c.Threshold) {
		return false
	}
	return true
}

// Threshold wraps a int64 and allows.
type Threshold int64

// WriteTo implements io.WriterTo interface.
func (t Threshold) WriteTo(w io.Writer) (int64, error) {
	intBuffer := make([]byte, 8)
	binary.BigEndian.PutUint64(intBuffer, uint64(t))
	n, err := w.Write(intBuffer)
	return int64(n), err
}

// Domain implements writer.WriterToWithDomain.
func (Threshold) Domain() string { return "Threshold" }
