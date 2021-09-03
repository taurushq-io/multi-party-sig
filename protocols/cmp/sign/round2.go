package sign

import (
	"errors"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/mta"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
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

type broadcast2 struct {
	round.ReliableBroadcastContent
	// K = Kᵢ
	K *paillier.Ciphertext
	// G = Gᵢ
	G *paillier.Ciphertext
}

type message2 struct {
	ProofEnc *zkenc.Proof
}

// StoreBroadcastMessage implements round.Round.
//
// - store Kⱼ, Gⱼ.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if !r.Paillier[from].ValidateCiphertexts(body.K, body.G) {
		return errors.New("invalid K, G")
	}

	r.K[from] = body.K
	r.G[from] = body.G

	return nil
}

// VerifyMessage implements round.Round.
//
// - verify zkenc(Kⱼ).
func (r *round2) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.ProofEnc == nil {
		return round.ErrNilFields
	}

	if !body.ProofEnc.Verify(r.Group(), r.HashForID(from), zkenc.Public{
		K:      r.K[from],
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}) {
		return errors.New("failed to validate enc proof for K")
	}
	return nil
}

// StoreMessage implements round.Round.
//
// - store Kⱼ, Gⱼ.
func (round2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - compute Hash(ssid, K₁, G₁, …, Kₙ, Gₙ).
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	if err := r.BroadcastMessage(out, &broadcast3{
		BigGammaShare: r.BigGammaShare[r.SelfID()],
	}); err != nil {
		return r, err
	}

	otherIDs := r.OtherPartyIDs()
	type mtaOut struct {
		err       error
		DeltaBeta *safenum.Int
		ChiBeta   *safenum.Int
	}
	mtaOuts := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]

		DeltaBeta, DeltaD, DeltaF, DeltaProof := mta.ProveAffG(r.Group(), r.HashForID(r.SelfID()),
			r.GammaShare, r.BigGammaShare[r.SelfID()], r.K[j],
			r.SecretPaillier, r.Paillier[j], r.Pedersen[j])
		ChiBeta, ChiD, ChiF, ChiProof := mta.ProveAffG(r.Group(),
			r.HashForID(r.SelfID()), curve.MakeInt(r.SecretECDSA), r.ECDSA[r.SelfID()], r.K[j],
			r.SecretPaillier, r.Paillier[j], r.Pedersen[j])

		proof := zklogstar.NewProof(r.Group(), r.HashForID(r.SelfID()),
			zklogstar.Public{
				C:      r.G[r.SelfID()],
				X:      r.BigGammaShare[r.SelfID()],
				Prover: r.Paillier[r.SelfID()],
				Aux:    r.Pedersen[j],
			}, zklogstar.Private{
				X:   r.GammaShare,
				Rho: r.GNonce,
			})

		err := r.SendMessage(out, &message3{
			DeltaD:     DeltaD,
			DeltaF:     DeltaF,
			DeltaProof: DeltaProof,
			ChiD:       ChiD,
			ChiF:       ChiF,
			ChiProof:   ChiProof,
			ProofLog:   proof,
		}, j)
		return mtaOut{
			err:       err,
			DeltaBeta: DeltaBeta,
			ChiBeta:   ChiBeta,
		}
	})
	DeltaShareBetas := make(map[party.ID]*safenum.Int, len(otherIDs)-1)
	ChiShareBetas := make(map[party.ID]*safenum.Int, len(otherIDs)-1)
	for idx, mtaOutRaw := range mtaOuts {
		j := otherIDs[idx]
		m := mtaOutRaw.(mtaOut)
		if m.err != nil {
			return r, m.err
		}
		DeltaShareBetas[j] = m.DeltaBeta
		ChiShareBetas[j] = m.ChiBeta
	}

	return &round3{
		round2:          r,
		DeltaShareBeta:  DeltaShareBetas,
		ChiShareBeta:    ChiShareBetas,
		DeltaShareAlpha: map[party.ID]*safenum.Int{},
		ChiShareAlpha:   map[party.ID]*safenum.Int{},
	}, nil
}

// RoundNumber implements round.Content.
func (message2) RoundNumber() round.Number { return 2 }

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return &message2{} }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (round2) BroadcastContent() round.BroadcastContent { return &broadcast2{} }

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }
