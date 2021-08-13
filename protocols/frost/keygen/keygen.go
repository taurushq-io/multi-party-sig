package keygen

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/types"
)

const (
	// Frost KeyGen with Threshold.
	protocolID types.ProtocolID = "frost/keygen-threshold"
	// This protocol has 3 concrete rounds.
	protocolRounds types.RoundNumber = 3
)

// These assert that our rounds implement the round.Round interface.
var (
	_ round.Round = (*round1)(nil)
	_ round.Round = (*round2)(nil)
	_ round.Round = (*round3)(nil)
)

func startKeygenCommon(taproot bool, group curve.Curve, participants []party.ID, threshold int, selfID party.ID) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		// Negative thresholds obviously make no sense.
		// We need threshold + 1 participants to sign, so if this number is larger
		// then the set of all participants, we can't ever generate signatures,
		// so the threshold makes no sense either.
		if threshold < 0 || threshold >= len(participants) {
			return nil, nil, fmt.Errorf("keygen.StartKeygen: invalid threshold: %d", threshold)
		}

		sortedIDs := party.NewIDSlice(participants)
		var taprootFlag byte
		if taproot {
			taprootFlag = 1
		}
		helper, err := round.NewHelper(
			protocolID,
			group,
			protocolRounds,
			selfID,
			sortedIDs,
			_Threshold(threshold),
			&hash.BytesWithDomain{
				TheDomain: "Taproot Flag",
				Bytes:     []byte{taprootFlag},
			},
		)
		if err != nil {
			return nil, nil, fmt.Errorf("keygen.StartKeygen: %w", err)
		}

		return &round1{
			Helper:    helper,
			taproot:   taproot,
			threshold: threshold,
		}, helper, nil
	}
}

// StartKeygen initiates the Frost key generation protocol.
//
// This protocol establishes a new threshold signature key among a set of participants.
// Later, a subset of these participants can create signatures for this public key,
// using the private shares created in this protocol.
//
// participants is a complete set of parties that will hold a share of the secret key.
// Future signers must come from this set.
//
// threshold is the number of participants that can be corrupted without breaking
// the security of the protocol. In the future, threshold + 1 participants will need
// to cooperate to produce signatures.
//
// selfID is the identifier for the local party calling this function.
//
// This protocol corresponds to Figure 1 of the Frost paper:
//   https://eprint.iacr.org/2020/852.pdf
func StartKeygen(group curve.Curve, participants []party.ID, threshold int, selfID party.ID) protocol.StartFunc {
	return startKeygenCommon(false, group, participants, threshold, selfID)
}

// StartKeygenTaproot is like StartKeygen, but will make Taproot / BIP-340 compatible keys.
//
// This will also return TaprootResult instead of Result, at the end of the protocol.
//
// See: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#specification
func StartKeygenTaproot(participants []party.ID, threshold int, selfID party.ID) protocol.StartFunc {
	return startKeygenCommon(true, curve.Secp256k1{}, participants, threshold, selfID)
}

// Threshold
type _Threshold int64

// WriteTo implements io.WriterTo interface.
func (t _Threshold) WriteTo(w io.Writer) (int64, error) {
	intBuffer := make([]byte, 8)
	binary.BigEndian.PutUint64(intBuffer, uint64(t))
	n, err := w.Write(intBuffer)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain
func (_Threshold) Domain() string { return "Threshold" }
