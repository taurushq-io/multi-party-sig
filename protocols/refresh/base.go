package refresh

import (
	"crypto/rand"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
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

var (
	_ round.Round = (*round1)(nil)
	_ round.Round = (*round2)(nil)
	_ round.Round = (*round3)(nil)
	_ round.Round = (*round4)(nil)
	_ round.Round = (*output)(nil)
)

// LocalParty is the state we store for a remote party.
// The messages are embedded to make access to the attributes easier.
type LocalParty struct {
	// Public is the struct for the new refreshed data. The Paillier and Pedersen fields are ignored.
	// The ECDSA field is the previous public key share if a refresh is being done, and the point at infinity otherwise.
	*Public

	// SchnorrCommitments is the Aⱼ used in the proof of knowledge in the last round
	SchnorrCommitments *curve.Point // Aⱼ

	// Commitment = H(msg3 ∥ Decommitment)
	Commitment hash.Commitment

	// RID = ρⱼ
	RID RID

	// VSSPolynomial = Fⱼ(X) = fⱼ(X)•G
	VSSPolynomial *polynomial.Exponent

	// ShareReceived = xʲᵢ is the share received from party j
	ShareReceived *curve.Scalar
}

func StartKeygen(partyIDs []party.ID, threshold int, selfID party.ID) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		SID, err := newSID(partyIDs, threshold)
		if err != nil {
			return nil, nil, fmt.Errorf("refresh.StartKeygen: %w", err)
		}
		helper := round.NewHelper(
			protocolKeygenID,
			protocolRounds,
			selfID,
			SID.partyIDs,
			SID.Hash(),
		)
		parties := make(map[party.ID]*LocalParty, len(partyIDs))
		for _, idJ := range partyIDs {
			// Set the public data to a clone of the current data
			parties[idJ] = &LocalParty{
				Public: &Public{
					ID:    idJ,
					ECDSA: curve.NewIdentityPoint(),
				},
			}
		}

		secret := sample.Scalar(rand.Reader)

		return &round1{
			Helper:  helper,
			SID:     SID,
			Self:    parties[selfID],
			Parties: parties,
			Secret: &Secret{
				ID:    selfID,
				ECDSA: curve.NewScalar(),
			},
			PublicKey: curve.NewIdentityPoint(),
			// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = secretᵢ
			VSSSecret: polynomial.NewPolynomial(threshold, secret),
		}, helper, nil
	}
}

func StartRefresh(s *Session, secret *Secret) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		selfID := secret.ID

		parties := make(map[party.ID]*LocalParty, len(s.public))
		for idJ, publicJ := range s.public {
			// Set the public data to a clone of the current data
			parties[idJ] = &LocalParty{
				Public: &Public{
					ID:    idJ,
					ECDSA: curve.NewIdentityPoint().Set(publicJ.ECDSA),
				},
			}
		}

		helper := round.NewHelper(
			protocolRefreshID,
			protocolRounds,
			selfID,
			s.partyIDs,
			s.Hash(),
		)

		return &round1{
			Helper:  helper,
			SID:     s.sid,
			Self:    parties[selfID],
			Parties: parties,
			Secret: &Secret{
				ID:    selfID,
				ECDSA: curve.NewScalar().Set(secret.ECDSA),
			},
			PublicKey: curve.FromPublicKey(s.publicKey),
			// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = 0
			VSSSecret: polynomial.NewPolynomial(s.threshold, nil),
		}, helper, nil
	}
}
