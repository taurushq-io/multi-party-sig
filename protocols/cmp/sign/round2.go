package sign

import (
	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/mta"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/message"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/types"
	zkenc "github.com/taurusgroup/multi-party-sig/pkg/zk/enc"
	zklogstar "github.com/taurusgroup/multi-party-sig/pkg/zk/logstar"
)

var _ round.Round = (*round2)(nil)

type round2 struct {
	*round1

	// K[j] = Kⱼ = encⱼ(kⱼ)
	K map[party.ID]*paillier.Ciphertext
	// G[j] = Gⱼ = encⱼ(γⱼ)
	G map[party.ID]*paillier.Ciphertext

	// BigGammaShare[j] = Γⱼ = [γⱼ]•G
	BigGammaShare map[party.ID]curve.Point

	// GammaShare = γᵢ <- 𝔽
	GammaShare *safenum.Int
	// KShare = kᵢ  <- 𝔽
	KShare curve.Scalar

	// KNonce = ρᵢ <- ℤₙ
	// used to encrypt Kᵢ = Encᵢ(kᵢ)
	KNonce *safenum.Nat
	// GNonce = νᵢ <- ℤₙ
	// used to encrypt Gᵢ = Encᵢ(γᵢ)
	GNonce *safenum.Nat
}

type Sign2 struct {
	ProofEnc *zkenc.Proof
	K        *paillier.Ciphertext
	G        *paillier.Ciphertext
}

// VerifyMessage implements round.Round.
//
// - verify zkenc(Kⱼ).
func (r *round2) VerifyMessage(from party.ID, to party.ID, content message.Content) error {
	body, ok := content.(*Sign2)
	if !ok || body == nil {
		return message.ErrInvalidContent
	}

	if body.ProofEnc == nil || body.G == nil || body.K == nil {
		return message.ErrNilContent
	}

	if !body.ProofEnc.Verify(r.HashForID(from), r.Group(), zkenc.Public{
		K:      body.K,
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}) {
		return ErrRound2ZKEnc
	}
	return nil
}

// StoreMessage implements round.Round.
//
// - store Kⱼ, Gⱼ.
func (r *round2) StoreMessage(from party.ID, content message.Content) error {
	body := content.(*Sign2)
	r.K[from] = body.K
	r.G[from] = body.G
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
		_ = h.WriteAny(r.K[j], r.G[j])
	}
	EchoHash := h.Sum()

	zkPrivate := zklogstar.Private{
		X:   r.GammaShare,
		Rho: r.GNonce,
	}

	DeltaMtA := map[party.ID]*mta.MtA{}
	DeltaShareBeta := map[party.ID]*safenum.Int{}
	ChiMtA := map[party.ID]*mta.MtA{}
	ChiShareBeta := map[party.ID]*safenum.Int{}

	// Broadcast the message we created in Round1
	otherIDs := r.OtherPartyIDs()
	errors := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]

		DeltaMtA[j], DeltaShareBeta[j] = mta.New(
			r.GammaShare, r.K[j],
			r.SecretPaillier, r.Paillier[j])
		ChiMtA[j], ChiShareBeta[j] = mta.New(
			curve.MakeInt(r.SecretECDSA), r.K[j],
			r.SecretPaillier, r.Paillier[j])

		proofLog := zklogstar.NewProof(r.Group(), r.HashForID(r.SelfID()), zklogstar.Public{
			C:      r.G[r.SelfID()],
			X:      r.BigGammaShare[r.SelfID()],
			Prover: r.Paillier[r.SelfID()],
			Aux:    r.Pedersen[j],
		}, zkPrivate)

		DeltaMtAProof := DeltaMtA[j].ProofAffG(r.Group(),
			r.HashForID(r.SelfID()), r.GammaShare, r.BigGammaShare[r.SelfID()], r.K[j], DeltaShareBeta[j],
			r.SecretPaillier, r.Paillier[j], r.Pedersen[j])
		ChiMtAProof := ChiMtA[j].ProofAffG(r.Group(),
			r.HashForID(r.SelfID()), curve.MakeInt(r.SecretECDSA), r.ECDSA[r.SelfID()], r.K[j], ChiShareBeta[j],
			r.SecretPaillier, r.Paillier[j], r.Pedersen[j])

		msg := r.MarshalMessage(&Sign3{
			EchoHash:      EchoHash,
			BigGammaShare: r.BigGammaShare[r.SelfID()],
			DeltaMtA:      DeltaMtAProof,
			ChiMtA:        ChiMtAProof,
			ProofLog:      proofLog,
		}, j)
		if err := r.SendMessage(msg, out); err != nil {
			return err
		}

		return nil
	})
	for _, err := range errors {
		if err != nil {
			return r, err.(error)
		}
	}

	return &round3{
		round2:          r,
		DeltaMtA:        DeltaMtA,
		ChiMtA:          ChiMtA,
		DeltaShareBeta:  DeltaShareBeta,
		ChiShareBeta:    ChiShareBeta,
		DeltaShareAlpha: map[party.ID]*safenum.Int{},
		ChiShareAlpha:   map[party.ID]*safenum.Int{},
		EchoHash:        EchoHash,
	}, nil
}

// MessageContent implements round.Round.
func (round2) MessageContent() message.Content { return &Sign2{} }

// RoundNumber implements message.Content.
func (Sign2) RoundNumber() types.RoundNumber { return 2 }
