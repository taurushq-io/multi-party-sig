package presign

import (
	"errors"
	"fmt"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/elgamal"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	zkaffg "github.com/taurusgroup/multi-party-sig/pkg/zk/affg"
	zkaffp "github.com/taurusgroup/multi-party-sig/pkg/zk/affp"
)

var _ round.Round = (*presign3)(nil)

type presign3 struct {
	*presign2
	// DeltaShareBeta[j] = βᵢⱼ
	DeltaShareBeta map[party.ID]*safenum.Int
	// ChiShareBeta[j] = β̂ᵢⱼ
	ChiShareBeta map[party.ID]*safenum.Int

	// DeltaCiphertext[j][k] = Dₖⱼ
	DeltaCiphertext map[party.ID]map[party.ID]*paillier.Ciphertext
	// ChiCiphertext[j][k] = D̂ₖⱼ
	ChiCiphertext map[party.ID]map[party.ID]*paillier.Ciphertext
}

type broadcast3 struct {
	round.NormalBroadcastContent
	// DeltaCiphertext[k] = Dₖⱼ
	DeltaCiphertext map[party.ID]*paillier.Ciphertext
	// ChiCiphertext[k] = D̂ₖⱼ
	ChiCiphertext map[party.ID]*paillier.Ciphertext
}

type message3 struct {
	DeltaF     *paillier.Ciphertext // DeltaF = Fᵢⱼ
	DeltaProof *zkaffp.Proof
	ChiF       *paillier.Ciphertext // ChiF = F̂ᵢⱼ
	ChiProof   *zkaffg.Proof
}

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *presign3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.DeltaCiphertext == nil || body.ChiCiphertext == nil {
		return round.ErrNilFields
	}

	for _, id := range r.PartyIDs() {
		if id == from {
			continue
		}
		DeltaCiphertext, ChiCiphertext := body.DeltaCiphertext[id], body.ChiCiphertext[id]
		if !r.Paillier[id].ValidateCiphertexts(DeltaCiphertext, ChiCiphertext) {
			return errors.New("received invalid ciphertext")
		}
	}

	r.DeltaCiphertext[from] = body.DeltaCiphertext
	r.ChiCiphertext[from] = body.ChiCiphertext
	return nil
}

// VerifyMessage implements round.Round.
//
// - verify zkaffg, zkaffp.
func (r *presign3) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if !body.DeltaProof.Verify(r.Group(), r.HashForID(from), zkaffp.Public{
		Kv:       r.K[to],
		Dv:       r.DeltaCiphertext[from][to],
		Fp:       body.DeltaF,
		Xp:       r.G[from],
		Prover:   r.Paillier[from],
		Verifier: r.Paillier[to],
		Aux:      r.Pedersen[to],
	}) {
		return errors.New("failed to validate affp proof for Delta MtA")
	}

	if !body.ChiProof.Verify(r.HashForID(from), zkaffg.Public{
		Kv:       r.K[to],
		Dv:       r.ChiCiphertext[from][to],
		Fp:       body.ChiF,
		Xp:       r.ECDSA[from],
		Prover:   r.Paillier[from],
		Verifier: r.Paillier[to],
		Aux:      r.Pedersen[to],
	}) {
		return errors.New("failed to validate affg proof for Chi MtA")
	}

	return nil
}

// StoreMessage implements round.Round.
func (presign3) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - Decrypt MtA shares,
// - save αᵢⱼ, α̂ᵢⱼ.
// - Γ = ∑ⱼ Γⱼ
// - Δᵢ = [kᵢ]Γ
// - δᵢ = γᵢ kᵢ + ∑ⱼ αᵢⱼ + βᵢⱼ
// - χᵢ = xᵢ kᵢ + ∑ⱼ α̂ᵢⱼ + β̂ᵢⱼ
// - Ẑⱼ, b̂ⱼ
func (r *presign3) Finalize(out chan<- *round.Message) (round.Session, error) {
	// δᵢ = γᵢ kᵢ
	KShareInt := curve.MakeInt(r.KShare)
	DeltaShare := new(safenum.Int).Mul(r.GammaShare, KShareInt, -1)

	DeltaSharesAlpha := make(map[party.ID]*safenum.Int, r.N())
	ChiSharesAlpha := make(map[party.ID]*safenum.Int, r.N())

	// χᵢ = xᵢ kᵢ
	ChiShare := new(safenum.Int).Mul(curve.MakeInt(r.SecretECDSA), KShareInt, -1)

	var (
		culprits []party.ID
		err      error
	)
	for _, j := range r.OtherPartyIDs() {
		// αᵢⱼ
		DeltaSharesAlpha[j], err = r.SecretPaillier.Dec(r.DeltaCiphertext[j][r.SelfID()])
		if err != nil {
			culprits = append(culprits, j)
			continue
		}
		// α̂ᵢⱼ
		ChiSharesAlpha[j], err = r.SecretPaillier.Dec(r.ChiCiphertext[j][r.SelfID()])
		if err != nil {
			culprits = append(culprits, j)
			continue
		}
		//δᵢ += αᵢⱼ + βᵢⱼ
		DeltaShare.Add(DeltaShare, DeltaSharesAlpha[j], -1)
		DeltaShare.Add(DeltaShare, r.DeltaShareBeta[j], -1)

		// χᵢ += α̂ᵢⱼ + β̂ᵢⱼ
		ChiShare.Add(ChiShare, ChiSharesAlpha[j], -1)
		ChiShare.Add(ChiShare, r.ChiShareBeta[j], -1)
	}
	if culprits != nil {
		return r.AbortRound(fmt.Errorf("failed to decrypt alpha shares for mta"), culprits...), nil
	}

	// ElGamalChi = Ẑⱼ = (b̂ⱼ⋅G, χᵢ+b̂ⱼ⋅Yᵢ)
	// ElGamalChiNonce = b̂ⱼ
	ElGamalChi, ElGamalChiNonce := elgamal.Encrypt(r.ElGamal[r.SelfID()], r.Group().NewScalar().SetNat(ChiShare.Mod(r.Group().Order())))

	DeltaShareScalar := r.Group().NewScalar().SetNat(DeltaShare.Mod(r.Group().Order()))

	msg := &broadcast4{
		DeltaShare: DeltaShareScalar,
		ElGamalChi: ElGamalChi,
	}
	if err = r.BroadcastMessage(out, msg); err != nil {
		return r, err
	}

	return &presign4{
		presign3:        r,
		DeltaShareAlpha: DeltaSharesAlpha,
		ChiShareAlpha:   ChiSharesAlpha,
		ElGamalChiNonce: ElGamalChiNonce,
		ElGamalChi:      map[party.ID]*elgamal.Ciphertext{r.SelfID(): ElGamalChi},
		DeltaShares:     map[party.ID]curve.Scalar{r.SelfID(): DeltaShareScalar},
		ChiShare:        r.Group().NewScalar().SetNat(ChiShare.Mod(r.Group().Order())),
	}, nil
}

// RoundNumber implements round.Content.
func (message3) RoundNumber() round.Number { return 3 }

// MessageContent implements round.Round.
func (r *presign3) MessageContent() round.Content {
	return &message3{ChiProof: zkaffg.Empty(r.Group())}
}

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (presign3) BroadcastContent() round.BroadcastContent { return &broadcast3{} }

// Number implements round.Round.
func (presign3) Number() round.Number { return 3 }

// BroadcastData implements broadcast.Broadcaster.
func (m broadcast3) BroadcastData() []byte {
	h := hash.New()
	ids := make([]party.ID, 0, len(m.DeltaCiphertext))
	for id := range m.DeltaCiphertext {
		ids = append(ids, id)
	}
	sortedIDs := party.NewIDSlice(ids)
	for _, id := range sortedIDs {
		_ = h.WriteAny(id, m.DeltaCiphertext[id], m.ChiCiphertext[id])
	}
	return h.Sum()
}
