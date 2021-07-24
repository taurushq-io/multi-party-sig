package sign

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/internal/writer"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
	"github.com/taurusgroup/cmp-ecdsa/protocols/cmp/keygen"
)

// protocolSignID for the "3 round" variant using echo broadcast.
const (
	protocolSignID     types.ProtocolID  = "cmp/sign-3-round-echo"
	protocolSignRounds types.RoundNumber = 5
)

var (
	_ round.Round = (*round1)(nil)
	_ round.Round = (*round2)(nil)
	_ round.Round = (*round3)(nil)
	_ round.Round = (*round4)(nil)
	_ round.Round = (*output)(nil)
)

func StartSign(s *keygen.Session, secret *keygen.Secret, signers []party.ID, message []byte) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		// validate session
		if err := s.Validate(); err != nil {
			return nil, nil, err
		}
		if err := s.ValidateSecret(secret); err != nil {
			return nil, nil, err
		}

		if len(message) == 0 {
			return nil, nil, errors.New("sign.Create: message is nil")
		}

		// check set of signers
		signerIDs := make(party.IDSlice, len(signers))
		copy(signerIDs, signers)
		signerIDs.Sort()

		if signerIDs.ContainsDuplicates() {
			return nil, nil, fmt.Errorf("sign.Create: signers contains duplicates")
		}

		if !s.PartyIDs().Contains(signerIDs...) {
			return nil, nil, fmt.Errorf("sign.Create: signers is not a subset of s.PartyIDs")
		}

		T := len(signerIDs)
		if T <= s.Threshold() {
			return nil, nil, fmt.Errorf("sign.Create: not enough signers: len(signers) = %d < threshold = %d", T, s.Threshold())
		}

		// Scale public data
		parties := make(map[party.ID]*keygen.Public, T)
		for _, partyJ := range signerIDs {
			publicJ := s.Public(partyJ)
			lagrange := signerIDs.Lagrange(partyJ)
			parties[partyJ] = &keygen.Public{
				ECDSA:    curve.NewIdentityPoint().ScalarMult(lagrange, publicJ.ECDSA),
				Paillier: publicJ.Paillier,
				Pedersen: publicJ.Pedersen,
			}
		}

		// Scale own secret
		lagrange := signerIDs.Lagrange(secret.ID)
		newSecret := secret.Clone()
		newSecret.ECDSA.Multiply(lagrange, newSecret.ECDSA)

		helper, err := round.NewHelper(
			protocolSignID,
			protocolSignRounds,
			secret.ID,
			signerIDs,
			s,
			signerIDs,
			writer.BytesWithDomain{
				TheDomain: "Signature Message",
				Bytes:     message,
			},
		)
		if err != nil {
			return nil, nil, fmt.Errorf("sign.Create: %w", err)
		}
		return &round1{
			Helper:    helper,
			Secret:    newSecret,
			PublicKey: s.PublicKey(),
			Public:    parties,
			Message:   message,
		}, helper, nil
	}
}
