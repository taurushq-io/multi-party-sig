package sign

import (
	"errors"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/cmp-ecdsa/internal/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol/types"
	zkenc "github.com/taurusgroup/cmp-ecdsa/pkg/zk/enc"
	zklogstar "github.com/taurusgroup/cmp-ecdsa/pkg/zk/logstar"
)

var _ round.Round = (*round2)(nil)

type round2 struct {
	*round1

	// K[j] = Kⱼ = encⱼ(kⱼ)
	K map[party.ID]*paillier.Ciphertext
	// G[j] = Gⱼ = encⱼ(γⱼ)
	G map[party.ID]*paillier.Ciphertext

	// BigGammaShare[j] = Γⱼ = [γⱼ]•G
	BigGammaShare map[party.ID]*curve.Point

	// GammaShare = γᵢ <- 𝔽
	GammaShare *curve.Scalar
	// KShare = kᵢ  <- 𝔽
	KShare *curve.Scalar

	// KNonce = ρᵢ <- ℤₙ
	// used to encrypt Kᵢ = Encᵢ(kᵢ)
	KNonce *safenum.Nat
	// GNonce = νᵢ <- ℤₙ
	// used to encrypt Gᵢ = Encᵢ(γᵢ)
	GNonce *safenum.Nat
}

// ProcessMessage implements round.Round.
//
// - store Kⱼ, Gⱼ
// - verify zkenc(Kⱼ).
func (r *round2) ProcessMessage(j party.ID, content message.Content) error {
	body := content.(*Sign2)

	if !body.ProofEnc.Verify(r.HashForID(j), zkenc.Public{
		K:      body.K,
		Prover: r.Paillier[j],
		Aux:    r.Pedersen[r.SelfID()],
	}) {
		return ErrRound2ZKEnc
	}

	r.K[j] = body.K
	r.G[j] = body.G
	return nil
}

// Finalize implements round.Round
//
// - compute Hash(ssid, K₁, G₁, …, Kₙ, Gₙ).
func (r *round2) Finalize(out chan<- *message.Message) (round.Round, error) {
	// compute Hash(ssid, K₁, G₁, …, Kₙ, Gₙ)
	// The papers says that we need to reliably broadcast this data, however unless we use
	// a system like white-city, we can't actually do this.
	// In the next round, if someone has a different hash, then we must abort, but there is no way of knowing who
	// was the culprit. We could maybe assume that we have an honest majority, but this clashes with the base assumptions.
	h := r.Hash()
	for _, j := range r.PartyIDs() {
		_, _ = h.WriteAny(r.K[j], r.G[j])
	}
	EchoHash := h.ReadBytes(nil)

	zkPrivate := zklogstar.Private{
		X:   r.GammaShare.Int(),
		Rho: r.GNonce,
	}

	DeltaMtA := map[party.ID]*MtA{}
	ChiMtA := map[party.ID]*MtA{}

	// Broadcast the message we created in round1
	for _, j := range r.OtherPartyIDs() {
		DeltaMtA[j] = NewMtA(
			r.GammaShare,
			r.BigGammaShare[r.SelfID()],
			r.K[r.SelfID()], r.K[j],
			r.SecretPaillier, r.Paillier[j])
		ChiMtA[j] = NewMtA(
			r.SecretECDSA,
			r.ECDSA[r.SelfID()],
			r.K[r.SelfID()], r.K[j],
			r.SecretPaillier, r.Paillier[j])

		proofLog := zklogstar.NewProof(r.HashForID(r.SelfID()), zklogstar.Public{
			C:      r.G[r.SelfID()],
			X:      r.BigGammaShare[r.SelfID()],
			Prover: r.Paillier[r.SelfID()],
			Aux:    r.Pedersen[j],
		}, zkPrivate)

		msg := r.MarshalMessage(&Sign3{
			EchoHash:      EchoHash,
			BigGammaShare: r.BigGammaShare[r.SelfID()],
			DeltaMtA:      DeltaMtA[j].ProofAffG(r.HashForID(r.SelfID()), r.Pedersen[j]),
			ChiMtA:        ChiMtA[j].ProofAffG(r.HashForID(r.SelfID()), r.Pedersen[j]),
			ProofLog:      proofLog,
		}, j)
		if err := r.SendMessage(msg, out); err != nil {
			return r, err
		}
	}

	return &round3{
		round2:   r,
		DeltaMtA: DeltaMtA,
		ChiMtA:   ChiMtA,
		EchoHash: EchoHash,
	}, nil
}

// MessageContent implements round.Round.
func (r *round2) MessageContent() message.Content { return &Sign2{} }

// Validate implements message.Content.
func (m *Sign2) Validate() error {
	if m == nil {
		return errors.New("sign.round2: message is nil")
	}
	if m.G == nil || m.K == nil {
		return errors.New("sign.round2: K or G is nil")
	}
	return nil
}

// RoundNumber implements message.Content.
func (m *Sign2) RoundNumber() types.RoundNumber { return 2 }
