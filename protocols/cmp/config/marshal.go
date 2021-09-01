package config

import (
	"errors"
	"fmt"

	"github.com/cronokirby/safenum"
	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
)

// EmptyConfig creates an empty Config with a fixed group, ready for unmarshalling.
//
// This needs to be used for unmarshalling, otherwise the points on the curve can't
// be decoded.
func EmptyConfig(group curve.Curve) *Config {
	return &Config{
		Group: group,
	}
}

type configMarshal struct {
	ID             party.ID
	Threshold      int
	ECDSA, ElGamal curve.Scalar
	P, Q           *safenum.Nat
	RID, ChainKey  types.RID
	Public         []cbor.RawMessage
}

type publicMarshal struct {
	ID             party.ID
	ECDSA, ElGamal curve.Point
	N              *safenum.Modulus
	S, T           *safenum.Nat
}

func (c *Config) MarshalBinary() ([]byte, error) {
	ps := make([]cbor.RawMessage, 0, len(c.Public))
	for _, id := range c.PartyIDs() {
		p := c.Public[id]
		pm := &publicMarshal{
			ID:      id,
			ECDSA:   p.ECDSA,
			ElGamal: p.ElGamal,
			N:       p.Pedersen.N(),
			S:       p.Pedersen.S(),
			T:       p.Pedersen.T(),
		}
		data, err := cbor.Marshal(pm)
		if err != nil {
			return nil, err
		}
		ps = append(ps, data)
	}
	return cbor.Marshal(&configMarshal{
		ID:        c.ID,
		Threshold: c.Threshold,
		ECDSA:     c.ECDSA,
		ElGamal:   c.ElGamal,
		P:         c.Paillier.P(),
		Q:         c.Paillier.Q(),
		RID:       c.RID,
		ChainKey:  c.ChainKey,
		Public:    ps,
	})
}

func (c *Config) UnmarshalBinary(data []byte) error {
	if c.Group == nil {
		return errors.New("config must be initialized using EmptyConfig")
	}
	cm := &configMarshal{
		ECDSA:   c.Group.NewScalar(),
		ElGamal: c.Group.NewScalar(),
	}
	if err := cbor.Unmarshal(data, &cm); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// check ECDSA, ElGamal
	if cm.ECDSA.IsZero() || cm.ElGamal.IsZero() {
		return errors.New("config: ECDSA or ElGamal secret key is zero")
	}

	// get Paillier secret key
	if err := paillier.ValidatePrime(cm.P); err != nil {
		return fmt.Errorf("config: prime P: %w", err)
	}
	if err := paillier.ValidatePrime(cm.Q); err != nil {
		return fmt.Errorf("config: prime Q: %w", err)
	}
	paillierSecret := paillier.NewSecretKeyFromPrimes(cm.P, cm.Q)

	// handle public parameters
	ps := make(map[party.ID]*Public, len(cm.Public))
	for _, pm := range cm.Public {
		p := &publicMarshal{
			ECDSA:   c.Group.NewPoint(),
			ElGamal: c.Group.NewPoint(),
		}
		if err := cbor.Unmarshal(pm, p); err != nil {
			return fmt.Errorf("config: party %s: %w", p.ID, err)
		}
		if _, ok := ps[p.ID]; ok {
			return fmt.Errorf("config: party %s: duplicate entry", p.ID)
		}

		// handle our own key separately
		if p.ID == cm.ID {
			ps[p.ID] = &Public{
				ECDSA:    cm.ECDSA.ActOnBase(),
				ElGamal:  cm.ElGamal.ActOnBase(),
				Paillier: paillierSecret.PublicKey,
				Pedersen: pedersen.New(paillierSecret.Modulus(), p.S, p.T),
			}
			continue
		}

		if err := paillier.ValidateN(p.N); err != nil {
			return fmt.Errorf("config: party %s: %w", p.ID, err)
		}
		if err := pedersen.ValidateParameters(p.N, p.S, p.T); err != nil {
			return fmt.Errorf("config: party %s: %w", p.ID, err)
		}
		if p.ECDSA.IsIdentity() || p.ElGamal.IsIdentity() {
			return fmt.Errorf("config: party %s: ECDSA or ElGamal public key is identity", p.ID)
		}

		paillierPublic := paillier.NewPublicKey(p.N)
		ps[p.ID] = &Public{
			ECDSA:    p.ECDSA,
			ElGamal:  p.ElGamal,
			Paillier: paillierPublic,
			Pedersen: pedersen.New(paillierPublic.Modulus(), p.S, p.T),
		}
	}

	// verify number of parties w.r.t. threshold
	// want 0 ⩽ threshold ⩽ n-1
	if !ValidThreshold(cm.Threshold, len(ps)) {
		return fmt.Errorf("config: threshold %d is invalid", cm.Threshold)
	}

	// check that we are included
	if _, ok := ps[cm.ID]; !ok {
		return errors.New("config: no public data for this party")
	}

	*c = Config{
		Group:     c.Group,
		ID:        cm.ID,
		Threshold: cm.Threshold,
		ECDSA:     cm.ECDSA,
		ElGamal:   cm.ElGamal,
		Paillier:  paillierSecret,
		RID:       cm.RID,
		ChainKey:  cm.ChainKey,
		Public:    ps,
	}
	return nil
}
