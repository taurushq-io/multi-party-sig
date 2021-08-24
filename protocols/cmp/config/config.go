package config

import (
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/bip32"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
)

// Public holds public information for a party
type Public struct {
	// ECDSA public key share
	ECDSA curve.Point
	// ElGamal is this party's public key for ElGamal encryption.
	ElGamal curve.Point
	// N = p•q, p ≡ q ≡ 3 mod 4
	N *safenum.Modulus
	// S = r² mod N
	S *safenum.Nat
	// T = Sˡ mod N
	T *safenum.Nat
}

// Config represents the SSID after having performed a keygen/refresh operation.
// It represents ssid = (sid, (N₁, s₁, t₁), …, (Nₙ, sₙ, tₙ))
// where sid = (𝔾, t, n, P₁, …, Pₙ).
type Config struct {
	Group curve.Curve

	ID party.ID

	// Threshold is the integer t which defines the maximum number of corruptions tolerated for this config.
	// Threshold + 1 is the minimum number of parties' shares required to reconstruct the secret/sign a message.
	Threshold int

	// ECDSA is this party's share xᵢ of the secret ECDSA x
	ECDSA curve.Scalar

	// ElGamal is this party's yᵢ used for ElGamal.
	ElGamal curve.Scalar

	// P, Q is the primes for N = P*Q used by Paillier and Pedersen
	P, Q *safenum.Nat

	// Public maps party.ID to party. It contains all public information associated to a party.
	Public map[party.ID]*Public

	// RID is a 32 byte random identifier generated for this config
	RID types.RID
	// ChainKey is the chaining key value associated with this public key
	ChainKey types.RID
}

// PublicPoint returns the group's public ECC point.
func (c Config) PublicPoint() curve.Point {
	sum := c.Group.NewPoint()
	partyIDs := make([]party.ID, 0, len(c.Public))
	for j := range c.Public {
		partyIDs = append(partyIDs, j)
	}
	l := polynomial.Lagrange(c.Group, partyIDs)
	for j, partyJ := range c.Public {
		sum = sum.Add(l[j].Act(partyJ.ECDSA))
	}
	return sum
}

// Validate ensures that the data is consistent. In particular it verifies:
// - 0 ⩽ threshold ⩽ n-1
// - all public data is present and valid
// - the secret corresponds to the data from an included party.
func (c Config) Validate() error {
	// verify number of parties w.r.t. threshold
	// want 0 ⩽ threshold ⩽ n-1
	if !ValidThreshold(int(c.Threshold), len(c.Public)) {
		return fmt.Errorf("config: threshold %d is invalid", c.Threshold)
	}

	if err := c.RID.Validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	if c.ECDSA == nil || c.P == nil || c.Q == nil {
		return errors.New("config: one or more field is empty")
	}

	// ECDSA is not identity
	if c.ECDSA.IsZero() {
		return errors.New("config: ECDSA secret key share is zero")
	}

	// Paillier check
	if err := paillier.ValidatePrime(c.P); err != nil {
		return fmt.Errorf("config: prime p: %w", err)
	}
	if err := paillier.ValidatePrime(c.Q); err != nil {
		return fmt.Errorf("config: prime q: %w", err)
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

	// verify ECDSA
	if !c.ECDSA.ActOnBase().Equal(public.ECDSA) {
		return errors.New("config: ECDSA private key share does not correspond with public key share")
	}

	// check ElGamal
	if ElGamalComputed := c.ElGamal.ActOnBase(); !ElGamalComputed.Equal(public.ElGamal) {
		return errors.New("config: ElGamal secret key does not correspond to public key")
	}

	// is the public ECDSA key equal
	pk := c.ECDSA.ActOnBase()
	if !pk.Equal(public.ECDSA) {
		return errors.New("config: ECDSA secret key share does not correspond to public share")
	}

	n := new(safenum.Nat).Mul(c.P, c.Q, -1)
	// is our public key for paillier the same?
	if public.N.Nat().Eq(n) != 1 {
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

// Paillier returns the secret Paillier key associated to this party.
func (c *Config) Paillier() *paillier.SecretKey {
	return paillier.NewSecretKeyFromPrimes(c.P, c.Q)
}

// WriteTo implements io.WriterTo interface.
func (c *Config) WriteTo(w io.Writer) (total int64, err error) {
	if c == nil {
		return 0, io.ErrUnexpectedEOF
	}
	var n int64

	// write t
	n, err = types.ThresholdWrapper(c.Threshold).WriteTo(w)
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
func (p *Public) WriteTo(w io.Writer) (total int64, err error) {
	if p == nil {
		return 0, io.ErrUnexpectedEOF
	}
	// write ECDSA
	data, err := p.ECDSA.MarshalBinary()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(data)
	if err != nil {
		return
	}
	total = int64(n)

	// write ElGamal
	data, err = p.ElGamal.MarshalBinary()
	if err != nil {
		return 0, err
	}
	n, err = w.Write(data)
	if err != nil {
		return
	}
	total += int64(n)

	buf := make([]byte, params.BytesIntModN)
	// write N, S, T
	for _, i := range []*safenum.Nat{p.N.Nat(), p.S, p.T} {
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
	if !ValidThreshold(c.Threshold, len(signers)) {
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

func ValidThreshold(t, n int) bool {
	if t < 0 || t > math.MaxUint32 {
		return false
	}
	if n <= 0 || t > n-1 {
		return false
	}
	return true
}

func (p *Public) Equal(other *Public) bool {
	if !p.ECDSA.Equal(other.ECDSA) {
		return false
	}
	if !p.ElGamal.Equal(other.ElGamal) {
		return false
	}
	if p.N.Nat().Eq(other.N.Nat()) != 1 {
		return false
	}
	if p.S.Eq(other.S) != 1 {
		return false
	}
	if p.T.Eq(other.T) != 1 {
		return false
	}
	return true
}

// DeriveChild derives a sharing of the ith child of the consortium signing key.
//
// This function uses unhardened derivation, deriving a key without including the
// underlying private key. This function will panic if i ⩾ 2³¹, since that indicates
// a hardened key.
//
// Sometimes, an error will be returned, indicating that this index generates
// an invalid key.
//
// See: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
func (c *Config) DeriveChild(i uint32) (*Config, error) {
	public, ok := c.PublicPoint().(*curve.Secp256k1Point)
	if !ok {
		return nil, errors.New("DeriveChild must be called with secp256k1")
	}
	scalar, newChainKey, err := bip32.DeriveScalar(public, c.ChainKey, i)
	if err != nil {
		return nil, err
	}

	// We need to add the scalar we've derived to the underlying secret,
	// for which it's sufficient to simply add it to each share. This means adding
	// scalar * G to each verification share as well.

	scalarG := scalar.ActOnBase()

	publics := make(map[party.ID]*Public, len(c.Public))
	for k, v := range c.Public {
		publics[k] = &Public{
			ECDSA:   v.ECDSA.Add(scalarG),
			ElGamal: v.ElGamal,
			N:       v.N,
			S:       v.S,
			T:       v.T,
		}
	}

	return &Config{
		Group:     c.Group,
		Threshold: c.Threshold,
		Public:    publics,
		RID:       c.RID,
		ChainKey:  newChainKey,
		ID:        c.ID,
		ECDSA:     c.Group.NewScalar().Set(c.ECDSA).Add(scalar),
		ElGamal:   c.ElGamal,
		P:         c.P,
		Q:         c.Q,
	}, nil
}
