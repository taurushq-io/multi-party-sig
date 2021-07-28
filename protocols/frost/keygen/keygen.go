package keygen

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
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
func StartKeygen(participants []party.ID, threshold int, selfID party.ID) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		// Negative thresholds obviously make no sense.
		// We need threshold + 1 participants to sign, so if this number is larger
		// then the set of all participants, we can't ever generate signatures,
		// so the threshold makes no sense either.
		if threshold < 0 || threshold >= len(participants) {
			return nil, nil, fmt.Errorf("keygen.StartKeygen: invalid threshold: %d", threshold)
		}

		sortedIDs := party.NewIDSlice(participants)
		helper, err := round.NewHelper(
			protocolID,
			protocolRounds,
			selfID,
			sortedIDs,
			_Threshold(threshold),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("keygen.StartKeygen: %w", err)
		}

		return &round1{
			Helper:    helper,
			threshold: threshold,
		}, helper, nil
	}
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

// Domain implements writer.WriterToWithDomain
func (_Threshold) Domain() string { return "Threshold" }
