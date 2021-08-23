package keygen

import (
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

const (
	// Frost KeyGen with Threshold.
	protocolID = "frost/keygen-threshold"
	// This protocol has 3 concrete rounds.
	protocolRounds round.Number = 3
)

// These assert that our rounds implement the round.Round interface.
var (
	_ round.Round = (*round1)(nil)
	_ round.Round = (*round2)(nil)
	_ round.Round = (*round3)(nil)
)

func StartKeygenCommon(taproot bool, group curve.Curve, participants []party.ID, threshold int, selfID party.ID) protocol.StartFunc {
	return func() (round.Round, *round.Info, error) {
		// Negative thresholds obviously make no sense.
		// We need threshold + 1 participants to sign, so if this number is larger
		// then the set of all participants, we can't ever generate signatures,
		// so the threshold makes no sense either.
		if threshold < 0 || threshold >= len(participants) {
			return nil, nil, fmt.Errorf("keygen.StartKeygen: invalid threshold: %d", threshold)
		}

		sortedIDs := party.NewIDSlice(participants)

		protocolString := protocolID
		if taproot {
			protocolString += "-taproot"
		}
		helper, err := round.NewHelper(
			protocolString,
			group,
			protocolRounds,
			selfID,
			sortedIDs,
			types.ThresholdWrapper(threshold),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("keygen.StartKeygen: %w", err)
		}

		return &round1{
			Helper:    helper,
			taproot:   taproot,
			threshold: threshold,
		}, helper.Info(), nil
	}
}
