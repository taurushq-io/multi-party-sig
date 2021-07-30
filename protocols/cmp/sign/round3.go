package sign

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/internal/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol/types"
	zklogstar "github.com/taurusgroup/cmp-ecdsa/pkg/zk/logstar"
)

var _ round.Round = (*round3)(nil)

type round3 struct {
	*round2

	DeltaMtA, ChiMtA map[party.ID]*MtA

	// EchoHash = Hash(ssid, K₁, G₁, …, Kₙ, Gₙ)
	// part of the echo of the first message
	EchoHash []byte
}

// ProcessMessage implements round.Round.
//
// - verify Hash(ssid, K₁, G₁, …, Kₙ, Gₙ)
// - store MtA data
// - verify zkproofs affg (2x) zklog*.
func (r *round3) ProcessMessage(j party.ID, content message.Content) error {
	body := content.(*Sign3)

	if !bytes.Equal(body.EchoHash, r.EchoHash) {
		return ErrRound3EchoHash
	}

	if err := r.DeltaMtA[j].Input(r.HashForID(j), r.Pedersen[r.SelfID()], body.DeltaMtA, body.BigGammaShare); err != nil {
		return fmt.Errorf("delta MtA: %w", ErrRound3ZKAffGDeltaMtA)
	}

	if err := r.ChiMtA[j].Input(r.HashForID(j), r.Pedersen[r.SelfID()], body.ChiMtA, r.ECDSA[j]); err != nil {
		return fmt.Errorf("chi MtA: %w", ErrRound3ZKAffGChiMtA)
	}

	zkLogPublic := zklogstar.Public{
		C:      r.G[j],
		X:      body.BigGammaShare,
		Prover: r.Paillier[j],
		Aux:    r.Pedersen[r.SelfID()],
	}
	if !body.ProofLog.Verify(r.HashForID(j), zkLogPublic) {
		return ErrRound3ZKLog
	}

	r.BigGammaShare[j] = body.BigGammaShare
	return nil
}

// Finalize implements round.Round
//
// - Γ = ∑ⱼ Γⱼ
// - Δᵢ = [kᵢ]Γ
// - δᵢ = γᵢ kᵢ + ∑ⱼ δᵢⱼ
// - χᵢ = xᵢ kᵢ + ∑ⱼ χᵢⱼ.
func (r *round3) Finalize(out chan<- *message.Message) (round.Round, error) {
	// Γ = ∑ⱼ Γⱼ
	Gamma := curve.NewIdentityPoint()
	for _, BigGammaShare := range r.BigGammaShare {
		Gamma.Add(Gamma, BigGammaShare)
	}

	// Δᵢ = [kᵢ]Γ
	BigDeltaShare := curve.NewIdentityPoint().ScalarMult(r.KShare, Gamma)

	// δᵢ = γᵢ kᵢ
	DeltaShare := curve.NewScalar().Multiply(r.GammaShare, r.KShare)

	// χᵢ = xᵢ kᵢ
	ChiShare := curve.NewScalar().Multiply(r.SecretECDSA, r.KShare)

	for _, j := range r.OtherPartyIDs() {
		// δᵢ += αᵢⱼ + βᵢⱼ
		DeltaShare.Add(DeltaShare, r.DeltaMtA[j].Share())

		// χᵢ += α̂ᵢⱼ +  ̂βᵢⱼ
		ChiShare.Add(ChiShare, r.ChiMtA[j].Share())
	}

	zkPrivate := zklogstar.Private{
		X:   r.KShare.Int(),
		Rho: r.KNonce,
	}

	for _, j := range r.OtherPartyIDs() {
		proofLog := zklogstar.NewProof(r.HashForID(r.SelfID()), zklogstar.Public{
			C:      r.K[r.SelfID()],
			X:      BigDeltaShare,
			G:      Gamma,
			Prover: r.Paillier[r.SelfID()],
			Aux:    r.Pedersen[j],
		}, zkPrivate)

		msg := r.MarshalMessage(&Sign4{
			DeltaShare:    DeltaShare,
			BigDeltaShare: BigDeltaShare,
			ProofLog:      proofLog,
		}, j)
		if err := r.SendMessage(msg, out); err != nil {
			return r, err
		}
	}

	return &round4{
		round3:         r,
		DeltaShares:    map[party.ID]*curve.Scalar{r.SelfID(): DeltaShare},
		BigDeltaShares: map[party.ID]*curve.Point{r.SelfID(): BigDeltaShare},
		Gamma:          Gamma,
		ChiShare:       ChiShare,
	}, nil
}

// MessageContent implements round.Round.
func (r *round3) MessageContent() message.Content { return &Sign3{} }

// Validate implements message.Content.
func (m *Sign3) Validate() error {
	if m == nil {
		return errors.New("sign.round3: message is nil")
	}
	if m.BigGammaShare == nil || m.DeltaMtA == nil || m.ChiMtA == nil || m.ProofLog == nil {
		return errors.New("sign.round3: message contains nil fields")
	}
	return nil
}

// RoundNumber implements message.Content.
func (m *Sign3) RoundNumber() types.RoundNumber { return 3 }
