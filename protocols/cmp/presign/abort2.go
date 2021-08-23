package presign

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	zklog "github.com/taurusgroup/multi-party-sig/pkg/zk/log"
)

var _ round.Round = (*abort2)(nil)

type abort2 struct {
	*presign7
	// YHat[j] = Ŷⱼ = bⱼ⋅Yⱼ
	YHat    map[party.ID]curve.Point
	KShares map[party.ID]curve.Scalar
	// ChiAlphas[j][k] = α̂ⱼₖ
	ChiAlphas map[party.ID]map[party.ID]curve.Scalar
}

type messageAbort2 struct {
	// YHat = Ŷⱼ = bⱼ⋅Yⱼ
	YHat      curve.Point
	YHatProof *zklog.Proof
	KProof    *abortNth
	ChiProofs map[party.ID]*abortNth
}

// VerifyMessage implements round.Round.
func (r *abort2) VerifyMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*messageAbort2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if !body.YHatProof.Verify(r.HashForID(from), zklog.Public{
		H: r.ElGamalK[from].L,
		X: r.ElGamal[from],
		Y: body.YHat,
	}) {
		return errors.New("failed to verify YHat log proof")
	}

	public := r.Paillier[from]
	if !body.KProof.Verify(r.HashForID(from), public, r.K[from]) {
		return errors.New("failed to verify validity of k")
	}

	for id, chiProof := range body.ChiProofs {
		if !chiProof.Verify(r.HashForID(from), public, r.ChiCiphertext[from][id]) {
			return errors.New("failed to validate Delta MtA Nth proof")
		}
	}

	return nil
}

// StoreMessage implements round.Round.
//
// - store Kⱼ, Gⱼ, Zⱼ.
func (r *abort2) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(*messageAbort2)
	alphas := make(map[party.ID]curve.Scalar, len(body.ChiProofs))
	for id, chiProof := range body.ChiProofs {
		alphas[id] = r.Group().NewScalar().SetNat(chiProof.Plaintext.Mod(r.Group().Order()))
	}
	r.ChiAlphas[from] = alphas
	r.YHat[from] = body.YHat
	r.KShares[from] = r.Group().NewScalar().SetNat(body.KProof.Plaintext.Mod(r.Group().Order()))
	return nil
}

// Finalize implements round.Round
func (r *abort2) Finalize(chan<- *round.Message) (round.Round, error) {
	var culprits []party.ID
	for _, j := range r.OtherPartyIDs() {
		// M = Ŷⱼ + kⱼ⋅Xⱼ
		M := r.Group().NewPoint().Add(r.YHat[j]).Add(r.KShares[j].Act(r.ECDSA[j]))
		for _, l := range r.PartyIDs() {
			if l == j {
				continue
			}
			M = M.Add(r.ChiAlphas[j][l].ActOnBase()) // α̂ⱼₗ⋅G
			M = M.Add(r.KShares[l].Act(r.ECDSA[j]))  // kₗ⋅Xⱼ
			M = M.Sub(r.ChiAlphas[l][j].ActOnBase()) // -α̂ₗⱼ⋅G

		}

		if !M.Equal(r.ElGamalK[j].M) {
			culprits = append(culprits, j)
		}
	}
	if len(culprits) > 0 {
		return &round.Output{Result: AbortResult{culprits}}, nil
	}
	//TODO better error
	return r, nil
}

// MessageContent implements round.Round.
func (abort2) MessageContent() round.Content {
	return &messageAbort2{}
}

// Number implements round.Round.
func (abort2) Number() round.Number { return 8 }

// Init implements round.Content.
func (m *messageAbort2) Init(group curve.Curve) {
	m.YHat = group.NewPoint()
	m.YHatProof = zklog.Empty(group)
}
