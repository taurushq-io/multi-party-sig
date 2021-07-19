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
	"github.com/taurusgroup/cmp-ecdsa/protocols/refresh"
)

// protocolSignID for the "3 round" variant using echo broadcast
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

func StartSign(s *refresh.Session, secret *refresh.Secret, signers []party.ID, message []byte) protocol.StartFunc {
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
		parties := make(map[party.ID]*LocalParty, T)
		for _, partyJ := range signerIDs {
			publicJ := s.Public(partyJ)
			lagrange := signerIDs.Lagrange(partyJ)
			parties[partyJ] = &LocalParty{
				Public: &refresh.Public{
					ID:       partyJ,
					ECDSA:    curve.NewIdentityPoint().ScalarMult(lagrange, publicJ.ECDSA),
					Paillier: publicJ.Paillier,
					Pedersen: publicJ.Pedersen,
				},
			}
		}

		// Scale own secret
		lagrange := signerIDs.Lagrange(secret.ID)
		newSecret := secret.Clone()
		newSecret.ECDSA.Multiply(lagrange, newSecret.ECDSA)

		// update hash with signing parties and message hash
		h := s.Hash()
		// write SignerIDs
		if _, err := h.WriteAny(signerIDs); err != nil {
			return nil, nil, fmt.Errorf("sign.Create: write signerIDs: %w", err)
		}

		// write Message
		if _, err := h.WriteAny(writer.BytesWithDomain{
			TheDomain: "Signature Message",
			Bytes:     message,
		}); err != nil {
			return nil, nil, fmt.Errorf("sign.Create: write message: %w", err)
		}

		helper := round.NewHelper(
			protocolSignID,
			protocolSignRounds,
			secret.ID,
			signerIDs,
			h,
		)
		return &round1{
			Helper:    helper,
			Self:      parties[secret.ID],
			Secret:    newSecret,
			PublicKey: s.PublicKey(),
			Parties:   parties,
			Message:   message,
		}, helper, nil
	}
}
