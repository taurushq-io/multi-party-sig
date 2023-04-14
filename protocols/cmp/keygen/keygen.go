package keygen

import (
	"crypto/rand"
	"fmt"

	"github.com/capsule-org/multi-party-sig/internal/round"
	"github.com/capsule-org/multi-party-sig/pkg/math/curve"
	"github.com/capsule-org/multi-party-sig/pkg/math/polynomial"
	"github.com/capsule-org/multi-party-sig/pkg/math/sample"
	"github.com/capsule-org/multi-party-sig/pkg/paillier"
	"github.com/capsule-org/multi-party-sig/pkg/party"
	"github.com/capsule-org/multi-party-sig/pkg/pool"
	"github.com/capsule-org/multi-party-sig/pkg/protocol"
	"github.com/capsule-org/multi-party-sig/protocols/cmp/config"
)

const Rounds round.Number = 5

func Start(info round.Info, pl *pool.Pool, c *config.Config, secretKey *paillier.SecretKey) protocol.StartFunc {
	return func(sessionID []byte) (_ round.Session, err error) {
		var helper *round.Helper
		if c == nil {
			helper, err = round.NewSession(info, sessionID, pl)
		} else {
			helper, err = round.NewSession(info, sessionID, pl, c)
		}
		if err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}

		group := helper.Group()

		if c != nil {
			PublicSharesECDSA := make(map[party.ID]curve.Point, len(c.Public))
			for id, public := range c.Public {
				PublicSharesECDSA[id] = public.ECDSA
			}
			return &round1{
				Helper:                    helper,
				PreviousSecretECDSA:       c.ECDSA,
				PreviousPublicSharesECDSA: PublicSharesECDSA,
				PreviousChainKey:          c.ChainKey,
				VSSSecret:                 polynomial.NewPolynomial(group, helper.Threshold(), group.NewScalar()), // fᵢ(X) deg(fᵢ) = t, fᵢ(0) = 0
			}, nil
		}

		// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = secretᵢ
		VSSConstant := sample.Scalar(rand.Reader, group)
		VSSSecret := polynomial.NewPolynomial(group, helper.Threshold(), VSSConstant)
		return &round1{
			Helper:            helper,
			VSSSecret:         VSSSecret,
			PaillierSecretKey: secretKey,
		}, nil

	}
}
