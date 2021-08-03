package keygen

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/cmp-ecdsa/internal/bip32"
	"github.com/taurusgroup/cmp-ecdsa/internal/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

// PublicPoint returns the group's public ECC point.
func (c Config) publicPoint() *curve.Point {
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
	return sum
}

// PublicKey returns the group's public ECDSA key.
func (c Config) PublicKey() *ecdsa.PublicKey {
	return c.publicPoint().ToPublicKey()
}

// Validate ensures that the data is consistent. In particular it verifies:
// - 0 ⩽ threshold ⩽ n-1
// - all public data is present and valid
// - the secret corresponds to the data from an included party.
func (c Config) Validate() error {
	// verify number of parties w.r.t. threshold
	// want 0 ⩽ threshold ⩽ n-1
	if !validThreshold(int(c.Threshold), len(c.Public)) {
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
	n, err = thresholdWrapper(c.Threshold).WriteTo(w)
	total += n
	if err != nil {
		return
	}

	// write partyIDs
	partyIDs := c.PartyIDs()
	n, err = partyIDs.WriteTo(w)
	total += n
	if err != nil {
		return
	}

	// write rid
	n, err = c.RID.WriteTo(w)
	total += n
	if err != nil {
		return
	}

	// write all party data
	for _, j := range partyIDs {
		// write Xⱼ
		n, err = c.Public[j].WriteTo(w)
		total += n
		if err != nil {
			return
		}
	}

	return
}

// Domain implements hash.WriterToWithDomain.
func (c Config) Domain() string {
	return "CMP Config"
}

// Domain implements hash.WriterToWithDomain.
func (Public) Domain() string {
	return "Public Data"
}

// WriteTo implements io.WriterTo interface.
func (p Public) WriteTo(w io.Writer) (total int64, err error) {
	// write ECDSA
	total, err = p.ECDSA.WriteTo(w)
	if err != nil {
		return
	}

	buf := make([]byte, params.BytesIntModN)
	var n int
	// write N, S, T
	for _, i := range []*big.Int{p.N, p.S, p.T} {
		i.FillBytes(buf)
		n, err = w.Write(buf)
		total += int64(n)
		if err != nil {
			return
		}
	}
	return
}

// CanSign returns true if the given _sorted_ list of signers is
// a valid subset of the original parties of size > t,
// and includes self.
func (c *Config) CanSign(signers party.IDSlice) bool {
	if !validThreshold(int(c.Threshold), len(signers)) {
		return false
	}

	// check for duplicates
	if !signers.Valid() {
		return false
	}

	if !signers.Contains(c.ID) {
		return false
	}

	// check that the signers are a subset of the original parties,
	// that it includes self, and that the size is > t.
	for _, j := range signers {
		if _, ok := c.Public[j]; !ok {
			return false
		}
	}

	return true
}

func validThreshold(t, n int) bool {
	if t < 0 || t > math.MaxUint32 {
		return false
	}
	if n <= 0 || t > n-1 {
		return false
	}
	return true
}

// DeriveChild derives a sharing of the ith child of the consortium signing key.
//
// This function uses unhardened derivation, deriving a key without including the
// underlying private key. This function will panic if i >= 2^31, since that indicates
// a hardened key.
//
// Sometimes, an error will be returned, indicating that this index generates
// an invalid key.
//
// See: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
func (c *Config) DeriveChild(i uint32) (*Config, error) {
	public := c.publicPoint()
	scalar, newChainKey, err := bip32.DeriveScalar(public, c.ChainKey, i)
	if err != nil {
		return nil, err
	}

	// We need to add the scalar we've derived to the underlying secret,
	// for which it's sufficient to simply add it to each share. This means adding
	// scalar * G to each verification share as well.

	scalarG := curve.NewIdentityPoint().ScalarBaseMult(scalar)

	publics := make(map[party.ID]*Public, len(c.Public))
	for k, v := range c.Public {
		publics[k] = &Public{
			ECDSA: curve.NewIdentityPoint().Add(scalarG, v.ECDSA),
			N:     v.N,
			S:     v.S,
			T:     v.T,
		}
	}

	return &Config{
		Threshold: c.Threshold,
		Public:    publics,
		RID:       c.RID,
		ChainKey:  newChainKey,
		Secret: &Secret{
			ID:    c.ID,
			ECDSA: curve.NewScalar().Add(scalar, c.ECDSA),
			P:     c.P,
			Q:     c.Q,
		},
	}, nil
}
