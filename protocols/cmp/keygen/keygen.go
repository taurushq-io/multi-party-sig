package keygen

import (
	"crypto/rand"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
)

const (
	// threshold keygen with echo broadcast
	protocolKeygenID types.ProtocolID = "cmp/keygen-threshold-echo"
	// threshold refresh with echo broadcast
	protocolRefreshID types.ProtocolID = "cmp/refresh-threshold-echo"

	protocolRounds types.RoundNumber = 6
)

func StartKeygen(partyIDs []party.ID, threshold int, selfID party.ID) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		sortedIDs := party.NewIDSlice(partyIDs)

		helper, err := round.NewHelper(
			protocolKeygenID,
			protocolRounds,
			selfID,
			sortedIDs,
			Threshold(threshold),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("keygen.StartKeygen: %w", err)
		}

		PreviousPublicSharesECDSA := make(map[party.ID]*curve.Point, len(partyIDs))
		for _, idJ := range sortedIDs {
			PreviousPublicSharesECDSA[idJ] = curve.NewIdentityPoint()
		}
		PreviousSecretECDSA := curve.NewScalar()
		PreviousPublicKey := curve.NewIdentityPoint()
		// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = secretᵢ
		VSSSecret := polynomial.NewPolynomial(threshold, sample.Scalar(rand.Reader))

		return &round1{
			Helper:                    helper,
			Threshold:                 threshold,
			PreviousPublicSharesECDSA: PreviousPublicSharesECDSA,
			PreviousSecretECDSA:       PreviousSecretECDSA,
			PreviousPublicKey:         PreviousPublicKey,
			VSSSecret:                 VSSSecret,
		}, helper, nil
	}
}

func StartRefresh(s *Session, secret *Secret) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		helper, err := round.NewHelper(
			protocolRefreshID,
			protocolRounds,
			secret.ID,
			s.PartyIDs(),
			s,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("refresh.StartKeygen: %w", err)
		}

		PreviousPublicSharesECDSA := make(map[party.ID]*curve.Point, len(s.public))
		for idJ, publicJ := range s.public {
			// Set the public data to a clone of the current data
			PreviousPublicSharesECDSA[idJ] = curve.NewIdentityPoint().Set(publicJ.ECDSA)
		}
		PreviousSecretECDSA := curve.NewScalar().Set(secret.ECDSA)
		PreviousPublicKey := curve.FromPublicKey(s.publicKey)
		// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = 0
		VSSSecret := polynomial.NewPolynomial(s.threshold, nil)

		return &round1{
			Helper:                    helper,
			Threshold:                 s.Threshold(),
			PreviousSecretECDSA:       PreviousSecretECDSA,
			PreviousPublicKey:         PreviousPublicKey,
			PreviousPublicSharesECDSA: PreviousPublicSharesECDSA,
			VSSSecret:                 VSSSecret,
		}, helper, nil
	}
}
