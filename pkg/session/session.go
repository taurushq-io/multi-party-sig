package session

import (
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

// State represents the latest stage accomplished
type State int

const (
	StateError State = iota
	StateInit
	StateKeygen
	StateRefresh
)

// Session contains information related to the current protocol session.
// It simplifies hashing using ssid to various types, and contains the (t,n) parameters
type Session struct {
	group     elliptic.Curve
	parties   party.IDSlice
	threshold int
	rid       []byte
	public    map[party.ID]*Public
}

func NewSessionKeygen(partyIDs []string, threshold int) (*Session, error) {
	n := len(partyIDs)
	public := make(map[party.ID]*Public, n)
	for _, id := range partyIDs {
		public[id] = &Public{ID: id}
	}
	parties := make(party.IDSlice, n)
	copy(parties, partyIDs)
	parties.Sort()
	s := &Session{
		group:     curve.Curve,
		parties:   parties,
		threshold: threshold,
		public:    public,
	}
	if err := s.Validate(nil); err != nil {
		return nil, err
	}
	return s, nil
}

func (s Session) NewFromKeygenResult(rid []byte, publicShares map[party.ID]*curve.Point) (*Session, error) {
	if s.state() != StateInit {
		return nil, errors.New("bad state transition")
	}

	public := make(map[party.ID]*Public, len(s.parties))
	for _, id := range s.parties {
		public[id] = NewPublic(id, publicShares[id], nil)
	}

	s2 := &Session{
		group:     s.group,
		parties:   s.parties.Copy(),
		threshold: s.threshold,
		rid:       append([]byte{}, rid...),
		public:    public,
	}

	if err := s2.Validate(nil); err != nil {
		return nil, err
	}
	return s2, nil
}

func (s Session) NewFromRefreshResult(publicShares map[party.ID]*curve.Point, ped map[party.ID]*pedersen.Parameters) (*Session, error) {
	if s.state() < StateKeygen {
		return nil, errors.New("bad state transition")
	}

	public := make(map[party.ID]*Public, len(s.parties))
	for _, id := range s.parties {
		public[id] = NewPublic(id, publicShares[id], ped[id])
	}

	s2 := &Session{
		group:     s.group,
		parties:   s.parties.Copy(),
		threshold: s.threshold,
		rid:       append([]byte{}, s.rid...),
		public:    public,
	}

	if err := s2.Validate(nil); err != nil {
		return nil, err
	}
	return s2, nil
}

func (s Session) Parties() party.IDSlice {
	return s.parties
}

// Public returns the map of all parties' public data
func (s Session) Public() map[party.ID]*Public {
	return s.public
}

func (s Session) N() int {
	return len(s.parties)
}

// Threshold returns the maximum number of corrupted parties allowed
func (s Session) Threshold() int {
	return s.threshold
}

// PublicKey returns the ECDSA public key for the session
func (s Session) PublicKey() (*curve.Point, error) {
	return getPublicKey(s.public)
}

// Validate checks all the parameters. If secret is not nil then it also checks if the secret agrees with the public data.
func (s Session) Validate(secret *Secret) error {
	// group
	if s.group == nil {
		return errors.New("group is nil")
	}

	if !s.parties.Sorted() {
		return errors.New("party list was not sorted")
	}

	n := len(s.parties)
	for _, j := range s.parties {
		publicJ, ok := s.public[j]
		if !ok {
			return fmt.Errorf("party %s: list mismatch with public parameters", j)
		}
		if j != publicJ.ID {
			return fmt.Errorf("party %s: id mismatch", j)
		}
		if err := publicJ.valid(); err != nil {
			return fmt.Errorf("party %s: %w", j, err)
		}
	}

	if len(s.public) != n {
		return errors.New("duplicated party id")
	}

	if s.threshold < 1 || s.threshold >= n {
		return errors.New("invalid threshold")
	}

	st := s.state()
	if st >= StateKeygen {
		if len(s.rid) != params.SecBytes {
			return errors.New("rid wrong length")
		}
	}

	if secret != nil {
		publicI, ok := s.public[secret.ID]
		if !ok {
			return errors.New("secret data does not correspond to any of the public party data")
		}

		if err := secret.validForParty(publicI); err != nil {
			return fmt.Errorf("secret data: %w", err)
		}
	}

	return nil
}

func (s *Session) SSID() []byte {
	out := make([]byte, params.HashBytes)
	h, err := s.Hash()
	if err != nil {
		panic(err)
	}
	_, _ = h.ReadBytes(out)
	return out
}

func (s *Session) Hash() (*hash.Hash, error) {
	var err error

	h := hash.New(nil)

	if _, err = h.Write([]byte(s.group.Params().Name)); err != nil {
		return nil, err
	} // 𝔾
	if _, err = h.Write(s.group.Params().N.Bytes()); err != nil {
		return nil, err
	} // q
	if _, err = h.Write(s.group.Params().Gx.Bytes()); err != nil {
		return nil, err
	} // gₓ

	if len(s.rid) != 0 {
		if _, err = h.Write(s.rid); err != nil {
			return nil, err
		}
	}

	idBuf := make([]byte, 8)
	// write n
	binary.BigEndian.PutUint64(idBuf, uint64(len(s.parties)))
	if _, err = h.Write(idBuf); err != nil {
		return nil, err
	}
	// write t
	binary.BigEndian.PutUint64(idBuf, uint64(s.threshold))
	if _, err = h.Write(idBuf); err != nil {
		return nil, err
	}

	// write all IDs
	for _, pid := range s.parties {
		if err = s.public[pid].writeToHash(h); err != nil {
			return nil, err
		}
	}

	return h, nil
}

func getPublicKey(parties map[party.ID]*Public) (*curve.Point, error) {
	pk := curve.NewIdentityPoint()
	for _, pi := range parties {
		if pi.state() < StateKeygen {
			return nil, errors.New("state does not have a public key")
		}
		pk.Add(pk, pi.ecdsaShare)
	}
	return pk, nil
}

func (s *Session) state() State {
	st := s.public[s.parties[0]].state()

	for _, p := range s.public {
		if st != p.state() {
			st = StateError
			break
		}
	}

	return st
}
