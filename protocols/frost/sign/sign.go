package sign

import (
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/frost/keygen"
)

const (
	// Frost Sign with Threshold.
	protocolID = "frost/sign-threshold"
	// This protocol has 3 concrete rounds.
	protocolRounds round.Number = 3
)

func StartSignCommon(taproot bool, err error, result *keygen.Result, signers []party.ID, messageHash []byte) protocol.StartFunc {
	return func() (round.Round, *round.Info, error) {
		group := result.Group
		// This is a bit of a hack, so that the Taproot can tell this function that the public key
		// is invalid.
		if err != nil {
			return nil, nil, err
		}
		sortedIDs := party.NewIDSlice(signers)
		var taprootFlag byte
		if taproot {
			taprootFlag = 1
		}
		helper, err := round.NewHelper(
			protocolID,
			group,
			protocolRounds,
			result.ID,
			sortedIDs,
			&hash.BytesWithDomain{
				TheDomain: "Taproot Flag",
				Bytes:     []byte{taprootFlag},
			},
		)
		if err != nil {
			return nil, nil, fmt.Errorf("sign.StartSign: %w", err)
		}
		// We delay this until *after* creating the helper, that way we know that
		// sortedIDs contains no duplicates.
		if result.Threshold+1 > sortedIDs.Len() {
			return nil, nil, fmt.Errorf("sign.StartSign: insufficient number of signers")
		}
		return &round1{
			Helper:  helper,
			taproot: taproot,
			M:       messageHash,
			Y:       result.PublicKey,
			YShares: result.VerificationShares,
			s_i:     result.PrivateShare,
		}, helper.Info(), nil
	}
}
