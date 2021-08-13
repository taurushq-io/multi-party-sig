package sign

import (
	"bytes"
	"fmt"

	"github.com/cronokirby/safenum"
	mta "github.com/taurusgroup/multi-party-sig/internal/mta"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/message"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/types"
	zklogstar "github.com/taurusgroup/multi-party-sig/pkg/zk/logstar"
)

var _ round.Round = (*round3)(nil)

type round3 struct {
	*round2

	DeltaMtA, ChiMtA map[party.ID]*mta.MtA

	// DeltaShareAlpha[j] = αᵢⱼ
	DeltaShareAlpha map[party.ID]*safenum.Int
	// DeltaShareBeta[j] = βᵢⱼ
	DeltaShareBeta map[party.ID]*safenum.Int
	// ChiShareAlpha[j] = α̂ᵢⱼ
	ChiShareAlpha map[party.ID]*safenum.Int
	// ChiShareBeta[j] =  ̂βᵢⱼ
	ChiShareBeta map[party.ID]*safenum.Int

	// EchoHash = Hash(ssid, K₁, G₁, …, Kₙ, Gₙ)
	// part of the echo of the first message
	EchoHash []byte
}

type Sign3 struct {
	// EchoHash = Hash(ssid, K₁, G₁, …, Kₙ, Gₙ)
	EchoHash      []byte
	BigGammaShare curve.Point
	DeltaMtA      *mta.Message
	ChiMtA        *mta.Message
	ProofLog      *zklogstar.Proof
}

// VerifyMessage implements round.Round.
//
// - verify Hash(ssid, K₁, G₁, …, Kₙ, Gₙ)
// - verify zkproofs affg (2x) zklog*.
func (r *round3) VerifyMessage(from party.ID, to party.ID, content message.Content) error {
	body, ok := content.(*Sign3)
	if !ok || body == nil {
		return message.ErrInvalidContent
	}

	if body.BigGammaShare == nil || body.DeltaMtA == nil || body.ChiMtA == nil || body.ProofLog == nil {
		return message.ErrNilContent
	}

	if !bytes.Equal(body.EchoHash, r.EchoHash) {
		return ErrRound3EchoHash
	}

	if err := r.DeltaMtA[from].VerifyAffG(r.HashForID(from), r.K[to], body.BigGammaShare, body.DeltaMtA, r.Paillier[from], r.Paillier[to], r.Pedersen[to]); err != nil {
		return fmt.Errorf("delta MtA: %w", ErrRound3ZKAffGDeltaMtA)
	}

	if err := r.ChiMtA[from].VerifyAffG(r.HashForID(from), r.K[to], r.ECDSA[from], body.ChiMtA, r.Paillier[from], r.Paillier[to], r.Pedersen[to]); err != nil {
		return fmt.Errorf("chi MtA: %w", ErrRound3ZKAffGChiMtA)
	}

	zkLogPublic := zklogstar.Public{
		C:      r.G[from],
		X:      body.BigGammaShare,
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}
	if !body.ProofLog.Verify(r.HashForID(from), zkLogPublic) {
		return ErrRound3ZKLog
	}

	return nil
}

// StoreMessage implements round.Round.
//
// - Decrypt MtA shares,
// - save Γⱼ, αᵢⱼ, α̂ᵢⱼ.
func (r *round3) StoreMessage(from party.ID, content message.Content) error {
	body := content.(*Sign3)

	r.BigGammaShare[from] = body.BigGammaShare

	ChiShareAlpha, err := body.ChiMtA.AlphaShare(r.SecretPaillier)
	if err != nil {
		return err
	}
	DeltaShareAlpha, err := body.DeltaMtA.AlphaShare(r.SecretPaillier)
	if err != nil {
		return err
	}

	r.ChiShareAlpha[from] = ChiShareAlpha
	r.DeltaShareAlpha[from] = DeltaShareAlpha

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
	Gamma := r.Group().NewPoint()
	for _, BigGammaShare := range r.BigGammaShare {
		Gamma.Add(BigGammaShare)
	}

	// Δᵢ = [kᵢ]Γ
	KShareInt := curve.MakeInt(r.KShare)
	BigDeltaShare := r.KShare.Act(Gamma)

	// δᵢ = γᵢ kᵢ
	DeltaShare := new(safenum.Int).Mul(r.GammaShare, KShareInt, -1)

	// χᵢ = xᵢ kᵢ
	ChiShare := new(safenum.Int).Mul(curve.MakeInt(r.SecretECDSA), KShareInt, -1)

	for _, j := range r.OtherPartyIDs() {
		//δᵢ += αᵢⱼ + βᵢⱼ
		DeltaShare.Add(DeltaShare, r.DeltaShareAlpha[j], -1)
		DeltaShare.Add(DeltaShare, r.DeltaShareBeta[j], -1)

		// χᵢ += α̂ᵢⱼ +  ̂βᵢⱼ
		ChiShare.Add(ChiShare, r.ChiShareAlpha[j], -1)
		ChiShare.Add(ChiShare, r.ChiShareBeta[j], -1)
	}

	zkPrivate := zklogstar.Private{
		X:   KShareInt,
		Rho: r.KNonce,
	}

	DeltaShareScalar := r.Group().NewScalar().SetNat(DeltaShare.Mod(r.Group().Order()))
	otherIDs := r.OtherPartyIDs()
	errors := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]

		proofLog := zklogstar.NewProof(r.Group(), r.HashForID(r.SelfID()), zklogstar.Public{
			C:      r.K[r.SelfID()],
			X:      BigDeltaShare,
			G:      Gamma,
			Prover: r.Paillier[r.SelfID()],
			Aux:    r.Pedersen[j],
		}, zkPrivate)

		msg := r.MarshalMessage(&Sign4{
			DeltaShare:    DeltaShareScalar,
			BigDeltaShare: BigDeltaShare,
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

	return &round4{
		round3:         r,
		DeltaShares:    map[party.ID]curve.Scalar{r.SelfID(): DeltaShareScalar},
		BigDeltaShares: map[party.ID]curve.Point{r.SelfID(): BigDeltaShare},
		Gamma:          Gamma,
		ChiShare:       r.Group().NewScalar().SetNat(ChiShare.Mod(r.Group().Order())),
	}, nil
}

// MessageContent implements round.Round.
func (r *round3) MessageContent() message.Content {
	return &Sign3{
		BigGammaShare: r.Group().NewPoint(),
		ProofLog:      zklogstar.Empty(r.Group()),
		DeltaMtA:      mta.Empty(r.Group()),
		ChiMtA:        mta.Empty(r.Group()),
	}
}

// RoundNumber implements message.Content.
func (Sign3) RoundNumber() types.RoundNumber { return 3 }
