package sign

import (
	"errors"
	"fmt"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	zkaffg "github.com/taurusgroup/multi-party-sig/pkg/zk/affg"
	zklogstar "github.com/taurusgroup/multi-party-sig/pkg/zk/logstar"
)

var _ round.Round = (*round3)(nil)

type round3 struct {
	*round2

	// DeltaShareAlpha[j] = αᵢⱼ
	DeltaShareAlpha map[party.ID]*safenum.Int
	// DeltaShareBeta[j] = βᵢⱼ
	DeltaShareBeta map[party.ID]*safenum.Int
	// ChiShareAlpha[j] = α̂ᵢⱼ
	ChiShareAlpha map[party.ID]*safenum.Int
	// ChiShareBeta[j] = β̂ᵢⱼ
	ChiShareBeta map[party.ID]*safenum.Int
}

type message3 struct {
	DeltaD     *paillier.Ciphertext // DeltaD = Dᵢⱼ
	DeltaF     *paillier.Ciphertext // DeltaF = Fᵢⱼ
	DeltaProof *zkaffg.Proof
	ChiD       *paillier.Ciphertext // DeltaD = D̂_{ij}
	ChiF       *paillier.Ciphertext // ChiF = F̂ᵢⱼ
	ChiProof   *zkaffg.Proof
	ProofLog   *zklogstar.Proof
}

type broadcast3 struct {
	round.NormalBroadcastContent
	BigGammaShare curve.Point // BigGammaShare = Γⱼ
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - store Γⱼ
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if body.BigGammaShare.IsIdentity() {
		return round.ErrNilFields
	}
	r.BigGammaShare[msg.From] = body.BigGammaShare
	return nil
}

// VerifyMessage implements round.Round.
//
// - verify zkproofs affg (2x) zklog*.
func (r *round3) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if !body.DeltaProof.Verify(r.HashForID(from), zkaffg.Public{
		Kv:       r.K[to],
		Dv:       body.DeltaD,
		Fp:       body.DeltaF,
		Xp:       r.BigGammaShare[from],
		Prover:   r.Paillier[from],
		Verifier: r.Paillier[to],
		Aux:      r.Pedersen[to],
	}) {
		return errors.New("failed to validate affg proof for Delta MtA")
	}

	if !body.ChiProof.Verify(r.HashForID(from), zkaffg.Public{
		Kv:       r.K[to],
		Dv:       body.ChiD,
		Fp:       body.ChiF,
		Xp:       r.ECDSA[from],
		Prover:   r.Paillier[from],
		Verifier: r.Paillier[to],
		Aux:      r.Pedersen[to],
	}) {
		return errors.New("failed to validate affg proof for Chi MtA")
	}

	if !body.ProofLog.Verify(r.HashForID(from), zklogstar.Public{
		C:      r.G[from],
		X:      r.BigGammaShare[from],
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}) {
		return errors.New("failed to validate log proof")
	}

	return nil
}

// StoreMessage implements round.Round.
//
// - Decrypt MtA shares,
// - save αᵢⱼ, α̂ᵢⱼ.
func (r *round3) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(*message3)

	// αᵢⱼ
	DeltaShareAlpha, err := r.SecretPaillier.Dec(body.DeltaD)
	if err != nil {
		return fmt.Errorf("failed to decrypt alpha share for delta: %w", err)
	}
	// α̂ᵢⱼ
	ChiShareAlpha, err := r.SecretPaillier.Dec(body.ChiD)
	if err != nil {
		return fmt.Errorf("failed to decrypt alpha share for chi: %w", err)
	}

	r.DeltaShareAlpha[from] = DeltaShareAlpha
	r.ChiShareAlpha[from] = ChiShareAlpha

	return nil
}

// Finalize implements round.Round
//
// - Γ = ∑ⱼ Γⱼ
// - Δᵢ = [kᵢ]Γ
// - δᵢ = γᵢ kᵢ + ∑ⱼ δᵢⱼ
// - χᵢ = xᵢ kᵢ + ∑ⱼ χᵢⱼ.
func (r *round3) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Γ = ∑ⱼ Γⱼ
	Gamma := r.Group().NewPoint()
	for _, BigGammaShare := range r.BigGammaShare {
		Gamma = Gamma.Add(BigGammaShare)
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
	if err := r.BroadcastMessage(out, &broadcast4{
		DeltaShare:    DeltaShareScalar,
		BigDeltaShare: BigDeltaShare,
	}); err != nil {
		return r, err
	}

	otherIDs := r.OtherPartyIDs()
	errs := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]

		proofLog := zklogstar.NewProof(r.Group(), r.HashForID(r.SelfID()), zklogstar.Public{
			C:      r.K[r.SelfID()],
			X:      BigDeltaShare,
			G:      Gamma,
			Prover: r.Paillier[r.SelfID()],
			Aux:    r.Pedersen[j],
		}, zkPrivate)

		err := r.SendMessage(out, &message4{
			ProofLog: proofLog,
		}, j)
		if err != nil {
			return err
		}
		return nil
	})
	for _, err := range errs {
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

// RoundNumber implements round.Content.
func (message3) RoundNumber() round.Number { return 3 }

// MessageContent implements round.Round.
func (r *round3) MessageContent() round.Content {
	return &message3{
		ProofLog:   zklogstar.Empty(r.Group()),
		DeltaProof: zkaffg.Empty(r.Group()),
		ChiProof:   zkaffg.Empty(r.Group()),
	}
}

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent {
	return &broadcast3{
		BigGammaShare: r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }
