package sign

import (
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/internal/writer"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
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

func StartSign(c *keygen.Config, signers []party.ID, message []byte) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		var err error
		// validate config
		if err = c.Validate(); err != nil {
			return nil, nil, err
		}

		if len(message) == 0 {
			return nil, nil, errors.New("sign.Create: message is nil")
		}

		// check set of signers
		signerIDs := party.NewIDSlice(signers)

		if signerIDs.ContainsDuplicates() {
			return nil, nil, fmt.Errorf("sign.Create: signers contains duplicates")
		}
		if !c.PartyIDs().Contains(signerIDs...) {
			return nil, nil, fmt.Errorf("sign.Create: signers is not a subset of s.PartyIDs")
		}

		T := len(signerIDs)
		if T <= int(c.Threshold) {
			return nil, nil, fmt.Errorf("sign.Create: not enough signers: len(signers) = %d < threshold = %d", T, c.Threshold)
		}

		lagrange := polynomial.Lagrange(signers)

		// Scale public data
		ECDSA := make(map[party.ID]*curve.Point, T)
		Paillier := make(map[party.ID]*paillier.PublicKey, T)
		Pedersen := make(map[party.ID]*pedersen.Parameters, T)
		PublicKey := curve.NewIdentityPoint()
		for _, j := range signerIDs {
			public := c.Public[j]
			ECDSA[j] = curve.NewIdentityPoint().ScalarMult(lagrange[j], public.ECDSA)
			if Paillier[j], err = paillier.NewPublicKey(public.N); err != nil {
				return nil, nil, err
			}
			if Pedersen[j], err = pedersen.New(public.N, public.S, public.T); err != nil {
				return nil, nil, err
			}
			PublicKey.Add(PublicKey, ECDSA[j])
		}

		// Scale own secret
		SecretECDSA := curve.NewScalar().Multiply(lagrange[c.ID], c.ECDSA)

		helper, err := round.NewHelper(
			protocolSignID,
			protocolSignRounds,
			c.ID,
			signerIDs,
			c,
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
			Helper:         helper,
			PublicKey:      PublicKey,
			SecretECDSA:    SecretECDSA,
			SecretPaillier: c.Paillier(),
			Paillier:       Paillier,
			Pedersen:       Pedersen,
			ECDSA:          ECDSA,
			Message:        message,
		}, helper, nil
	}
}
