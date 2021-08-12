package keygen

import (
	"crypto/rand"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/types"
)

const (
	// threshold keygen with echo broadcast.
	protocolKeygenID types.ProtocolID = "cmp/keygen-threshold-echo"
	// threshold refresh with echo broadcast.
	protocolRefreshID types.ProtocolID = "cmp/refresh-threshold-echo"

	protocolRounds types.RoundNumber = 6
)

func StartKeygen(pl *pool.Pool, group curve.Curve, partyIDs []party.ID, threshold int, selfID party.ID) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {

		sortedIDs := party.NewIDSlice(partyIDs)

		n := len(sortedIDs)
		if !validThreshold(threshold, n) {
			return nil, nil, fmt.Errorf("keygen.StartKeygen: threshold %d is not valid for number of parties %d", threshold, n)
		}
		helper, err := round.NewHelper(
			protocolKeygenID,
			group,
			protocolRounds,
			selfID,
			sortedIDs,
			thresholdWrapper(threshold),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("keygen.StartKeygen: %w", err)
		}

		PreviousPublicSharesECDSA := make(map[party.ID]curve.Point, n)
		for _, idJ := range helper.PartyIDs() {
			PreviousPublicSharesECDSA[idJ] = group.NewPoint()
		}
		PreviousSecretECDSA := group.NewScalar()
		PreviousPublicKey := group.NewPoint()
		// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = secretᵢ
		VSSSecret := polynomial.NewPolynomial(group, threshold, sample.Scalar(rand.Reader, group))

		return &round1{
			Helper:                    helper,
			Pool:                      pl,
			Threshold:                 threshold,
			PreviousPublicSharesECDSA: PreviousPublicSharesECDSA,
			PreviousSecretECDSA:       PreviousSecretECDSA,
			PreviousPublicKey:         PreviousPublicKey,
			PreviousChainKey:          nil,
			VSSSecret:                 VSSSecret,
		}, helper, nil
	}
}

func StartRefresh(pl *pool.Pool, c *Config) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		group := c.Group

		partyIDs := c.PartyIDs()
		helper, err := round.NewHelper(
			protocolRefreshID,
			group,
			protocolRounds,
			c.ID,
			partyIDs,
			c,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("refresh.StartKeygen: %w", err)
		}

		PreviousPublicSharesECDSA := make(map[party.ID]curve.Point, len(partyIDs))
		for _, j := range partyIDs {
			// Set the public data to a clone of the current data
			PreviousPublicSharesECDSA[j] = group.NewPoint().Set(c.Public[j].ECDSA)
		}
		PreviousSecretECDSA := group.NewScalar().Set(c.ECDSA)
		PreviousPublicKey := group.NewPoint().Set(c.PublicPoint())
		// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = 0
		VSSSecret := polynomial.NewPolynomial(group, int(c.Threshold), nil)

		return &round1{
			Helper:                    helper,
			Pool:                      pl,
			Threshold:                 int(c.Threshold),
			PreviousSecretECDSA:       PreviousSecretECDSA,
			PreviousPublicKey:         PreviousPublicKey,
			PreviousPublicSharesECDSA: PreviousPublicSharesECDSA,
			PreviousChainKey:          c.ChainKey,
			VSSSecret:                 VSSSecret,
		}, helper, nil
	}
}
