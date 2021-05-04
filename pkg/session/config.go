package session

import (
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"sort"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"golang.org/x/crypto/sha3"
)

type Config struct {
	curve    elliptic.Curve
	partyIDs party.IDSlice
	selfID   party.ID
	selfIdx  int
	n        int

	sidExtra, ssidExtra []byte
}

func NewConfig(selfID string, partyIDs []string) (*Config, error) {
	sorted := make(party.IDSlice, len(partyIDs))
	copy(sorted, partyIDs)
	sort.Sort(sorted)

	selfIdx := -1
	if sorted[0] == selfID {
		selfIdx = 0
	}

	for i := 1; i < len(sorted); i++ {
		if sorted[i-1] == sorted[i] {
			return nil, errors.New("partyIDs contains duplicated")
		}
		if sorted[i] == selfID {
			selfIdx = i
		}
	}

	if selfIdx == -1 {
		return nil, errors.New("selfID not included in partyIDs")
	}

	return &Config{
		curve:    curve.Curve,
		partyIDs: sorted,
		selfID:   selfID,
		selfIdx:  selfIdx,
		n:        len(sorted),
	}, nil
}

// SelfID is the ID of the party
func (c Config) SelfID() party.ID {
	return c.selfID
}

// SelfIndex returns the index in Parties of SelfID when Parties is sorted
func (c Config) SelfIndex() int {
	return c.selfIdx
}

// N returns the number of parties participating in the protocol
func (c Config) N() int {
	return c.n
}

// SID generates a new hash of the session ID.
// It bind the information about the parties and the curve used.
func (c Config) SID() []byte {
	out := make([]byte, params.HashBytes)
	_, _ = c.hashSID().Read(out)
	return out
}

func (c Config) hashSID() sha3.ShakeHash {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte(c.curve.Params().Name)) // 𝔾
	_, _ = h.Write(c.curve.Params().N.Bytes())    // q
	_, _ = h.Write(c.curve.Params().Gx.Bytes())   // gₓ

	idBuf := make([]byte, 4)
	// write n
	binary.BigEndian.PutUint32(idBuf, uint32(len(c.partyIDs)))
	_, _ = h.Write(idBuf) // n

	// write all ids
	for _, pid := range c.partyIDs {
		_, _ = h.Write([]byte(pid)) // id
	}

	if len(c.sidExtra) != 0 {
		_, _ = h.Write(c.sidExtra)
	}
	return h
}

// SSID generates a new hash of the secure (?) session ID.
// It depends on the SID, as well as any other relevant parameters.
func (c Config) SSID() []byte {
	out := make([]byte, params.HashBytes)
	h := c.hashSID()

	if len(c.ssidExtra) != 0 {
		_, _ = h.Write(c.ssidExtra)
	}

	_, _ = h.Read(out)
	return out
}

func (c *Config) SetSSIDExtra(extra []byte) {
	c.ssidExtra = extra
}

func (c *Config) SetSIDExtra(extra []byte) {
	c.sidExtra = extra
}

// Curve returns the elliptic.Curve used
func (c Config) Curve() elliptic.Curve {
	return c.curve
}

// Parties is a sorted list of party IDs
func (c Config) Parties() party.IDSlice {
	return c.partyIDs
}
