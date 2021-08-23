package presign

import (
	"errors"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	zkelog "github.com/taurusgroup/multi-party-sig/pkg/zk/elog"
)

var _ round.Round = (*presign6)(nil)

type presign6 struct {
	*presign5

	// BigDeltaShares[j] = Δⱼ = [kⱼ]•Γⱼ
	BigDeltaShares map[party.ID]curve.Point

	// Gamma = ∑ᵢ Γᵢ
	Gamma curve.Point
}

type message6 struct {
	// BigDeltaShare = Δⱼ = [kⱼ]•Γⱼ
	BigDeltaShare curve.Point
	Proof         *zkelog.Proof
}

// VerifyMessage implements round.Round.
func (r *presign6) VerifyMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*message6)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.BigDeltaShare.IsIdentity() {
		return round.ErrNilFields
	}

	if !body.Proof.Verify(r.HashForID(from), zkelog.Public{
		E:             r.ElGamalK[from],
		ElGamalPublic: r.ElGamal[from],
		Base:          r.Gamma,
		Y:             body.BigDeltaShare,
	}) {
		return errors.New("failed to validate elog proof for BigDeltaShare")
	}

	return nil
}

// StoreMessage implements round.Round.
//
// - save Δⱼ
func (r *presign6) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(*message6)
	r.BigDeltaShares[from] = body.BigDeltaShare
	return nil
}

// Finalize implements round.Round
//
// - compute δ = ∑ⱼ δⱼ,
// - compute R = [δ⁻¹] Γ,
// - compute Sᵢ = χᵢ⋅R,
// - compute {R̄ⱼ = δ⁻¹⋅Δⱼ}ⱼ.
func (r *presign6) Finalize(out chan<- *round.Message) (round.Round, error) {
	// δ = ∑ⱼ δⱼ
	Delta := r.Group().NewScalar()
	for _, DeltaJ := range r.DeltaShares {
		Delta.Add(DeltaJ)
	}

	// δ⁻¹
	DeltaInv := r.Group().NewScalar().Set(Delta).Invert()

	// R = [δ⁻¹] Γ
	R := DeltaInv.Act(r.Gamma)

	// δ⋅G
	BigDeltaExpected := Delta.ActOnBase()

	// ∑ⱼΔⱼ
	BigDeltaActual := r.Group().NewPoint()
	for _, BigDeltaJ := range r.BigDeltaShares {
		BigDeltaActual = BigDeltaActual.Add(BigDeltaJ)
	}

	// δ⋅G ?= ∑ⱼΔⱼ
	if !BigDeltaActual.Equal(BigDeltaExpected) {
		DeltaProofs := make(map[party.ID]*abortNth, r.N()-1)
		for _, j := range r.OtherPartyIDs() {
			deltaCiphertext := r.DeltaCiphertext[j][r.SelfID()] // Dᵢⱼ
			DeltaProofs[j] = proveNth(r.HashForID(r.SelfID()), r.SecretPaillier, deltaCiphertext)
		}
		msg := &messageAbort1{
			GammaShare:  r.GammaShare,
			KProof:      proveNth(r.HashForID(r.SelfID()), r.SecretPaillier, r.K[r.SelfID()]),
			DeltaProofs: DeltaProofs,
		}
		if err := r.SendMessage(out, msg, ""); err != nil {
			return r, err
		}
		return &abort1{
			presign6:    r,
			GammaShares: map[party.ID]*safenum.Int{r.SelfID(): r.GammaShare},
			KShares:     map[party.ID]*safenum.Int{r.SelfID(): curve.MakeInt(r.KShare)},
			DeltaAlphas: map[party.ID]map[party.ID]*safenum.Int{r.SelfID(): r.DeltaShareAlpha},
		}, nil
	}

	// Sᵢ = χᵢ⋅R,
	S := r.ChiShare.Act(R)

	// {R̄ⱼ = δ⁻¹⋅Δⱼ}ⱼ
	RBar := make(map[party.ID]curve.Point, r.N())
	for j, BigDeltaJ := range r.BigDeltaShares {
		RBar[j] = DeltaInv.Act(BigDeltaJ)
	}

	proof := zkelog.NewProof(r.Group(), r.HashForID(r.SelfID()), zkelog.Public{
		E:             r.ElGamalChi[r.SelfID()],
		ElGamalPublic: r.ElGamal[r.SelfID()],
		Base:          R,
		Y:             S,
	}, zkelog.Private{
		Y:      r.ChiShare,
		Lambda: r.ElGamalChiNonce,
	})

	err := r.SendMessage(out, &message7{
		S:              S,
		Proof:          proof,
		DecommitmentID: r.DecommitmentID,
		PresignatureID: r.PresignatureID[r.SelfID()],
	}, "")
	if err != nil {
		return r, err.(error)
	}

	return &presign7{
		presign6: r,
		Delta:    Delta,
		S:        map[party.ID]curve.Point{r.SelfID(): S},
		R:        R,
		RBar:     RBar,
	}, nil
}

// MessageContent implements round.Round.
func (presign6) MessageContent() round.Content { return &message6{} }

// Number implements round.Round.
func (presign6) Number() round.Number { return 6 }

// Init implements round.Content.
func (m *message6) Init(group curve.Curve) {
	m.BigDeltaShare = group.NewPoint()
	m.Proof = zkelog.Empty(group)
}