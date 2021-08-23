package keygen

import (
	"crypto/rand"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/config"
)

const protocolRounds round.Number = 5

const (
	// threshold keygen with echo broadcast.
	protocolKeygenID = "cmp/keygen-threshold"
	// threshold refresh with echo broadcast.
	protocolRefreshID = "cmp/refresh-threshold"
)

func StartKeygen(pl *pool.Pool, group curve.Curve, partyIDs []party.ID, threshold int, selfID party.ID) protocol.StartFunc {
	PublicSharesECDSA := make(map[party.ID]curve.Point, len(partyIDs))
	for _, idJ := range partyIDs {
		PublicSharesECDSA[idJ] = group.NewPoint()
	}
	return Start(pl, protocolKeygenID, group, selfID, party.NewIDSlice(partyIDs), threshold, group.NewPoint(), PublicSharesECDSA, group.NewScalar(), nil, types.ThresholdWrapper(threshold))
}

func StartRefresh(pl *pool.Pool, c *config.Config) protocol.StartFunc {
	group := c.Group
	partyIDs := c.PartyIDs()
	PublicSharesECDSA := make(map[party.ID]curve.Point, len(partyIDs))
	for _, idJ := range partyIDs {
		PublicSharesECDSA[idJ] = c.Public[idJ].ECDSA
	}
	return Start(pl, protocolRefreshID, group, c.ID, partyIDs, int(c.Threshold), c.PublicPoint(), PublicSharesECDSA, c.ECDSA, c.ChainKey, c)
}

func Start(pl *pool.Pool, protocolID string, group curve.Curve, id party.ID, partyIDs party.IDSlice, threshold int,
	PublicPoint curve.Point, PublicSharesECDSA map[party.ID]curve.Point, SecretShareECDSA curve.Scalar, chainKey []byte,
	thresholdOrConfig hash.WriterToWithDomain,
) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		if !config.ValidThreshold(threshold, len(partyIDs)) {
			return nil, nil, fmt.Errorf("keygen.StartKeygen: threshold %d is not valid for number of parties %d", threshold, len(partyIDs))
		}

		helper, err := round.NewHelper(
			protocolID,
			group,
			protocolRounds,
			id,
			partyIDs,
			thresholdOrConfig,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("refresh.StartKeygen: %w", err)
		}

		VSSConstant := group.NewScalar()
		if SecretShareECDSA.IsZero() {
			// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = secretᵢ
			VSSConstant = sample.Scalar(rand.Reader, group)
		}

		// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = 0
		VSSSecret := polynomial.NewPolynomial(group, threshold, VSSConstant)

		return &round1{
			Helper:                    helper,
			Pool:                      pl,
			Threshold:                 threshold,
			PreviousSecretECDSA:       SecretShareECDSA,
			PreviousPublicKey:         PublicPoint,
			PreviousPublicSharesECDSA: PublicSharesECDSA,
			PreviousChainKey:          chainKey,
			VSSSecret:                 VSSSecret,
		}, helper, nil
	}
}
