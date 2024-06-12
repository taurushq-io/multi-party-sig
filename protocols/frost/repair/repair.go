package repair

import (
	"fmt"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"slices"
)

// code is largely based on key repair code in
// https://github.com/ZcashFoundation/frost/tree/main
// see also https://github.com/siv2r/frost-enrollment

const (
	protocolID                  = "frost/repair"
	protocolRounds round.Number = 3
)

// These assert that our rounds implement the round.Round interface.
var (
	_ round.Round = (*round1)(nil)
	_ round.Round = (*round2)(nil)
	_ round.Round = (*round3)(nil)
)

func Repair(helpers []party.ID, lostID, selfID party.ID, privateShare curve.Scalar) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		if len(helpers) < 2 {
			return nil, fmt.Errorf(
				"repair.Repair: not enough helpers (wanted 2+), have %d", len(helpers))
		}

		if lostID == selfID {
			if privateShare != nil {
				return nil, fmt.Errorf(
					"repair.Repair: private share should be nil for lost share")
			}
			if slices.ContainsFunc(helpers, func(id party.ID) bool { return id == lostID }) {
				return nil, fmt.Errorf(
					"repair.Repair: lost share ID (%v) should not be in helpers (%v)", lostID, helpers)
			}
		} else {
			if privateShare == nil {
				return nil, fmt.Errorf(
					"repair.Repair: private share should not be nil for helper share")
			}
			if !slices.ContainsFunc(helpers, func(id party.ID) bool { return id == selfID }) {
				return nil, fmt.Errorf(
					"repair.Repair: self ID (%v) should be in helpers (%v)", selfID, helpers)
			}
		}

		participants := make(party.IDSlice, 0, len(helpers)+1)
		participants = append(participants, helpers...)
		participants = append(participants, lostID)

		info := round.Info{
			ProtocolID:       protocolID,
			FinalRoundNumber: protocolRounds,
			SelfID:           selfID,
			PartyIDs:         participants,
			Group:            curve.Secp256k1{},
		}
		Helper, err := round.NewSession(info, sessionID, nil)
		if err != nil {
			return nil, fmt.Errorf("repair.Repair: %w", err)
		}
		return &round1{Helper, helpers, lostID, privateShare}, nil
	}
}
