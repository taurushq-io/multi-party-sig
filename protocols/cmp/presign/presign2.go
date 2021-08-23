package presign

import (
	"errors"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/broadcast"
	"github.com/taurusgroup/multi-party-sig/internal/elgamal"
	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/internal/mta"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	zkaffg "github.com/taurusgroup/multi-party-sig/pkg/zk/affg"
	zkaffp "github.com/taurusgroup/multi-party-sig/pkg/zk/affp"
	zkencelg "github.com/taurusgroup/multi-party-sig/pkg/zk/encelg"
)

var _ round.Round = (*presign2)(nil)

type presign2 struct {
	*presign1

	// K[j] = Kⱼ = encⱼ(kⱼ)
	K map[party.ID]*paillier.Ciphertext
	// G[j] = Gⱼ = encⱼ(γⱼ)
	G map[party.ID]*paillier.Ciphertext

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

	// ElGamalKNonce = bᵢ
	ElGamalKNonce elgamal.Nonce
	// ElGamalK[j] = Zⱼ
	ElGamalK map[party.ID]*elgamal.Ciphertext

	// PresignatureID[j] = idⱼ
	PresignatureID map[party.ID]types.RID
	// CommitmentID[j] = Com(idⱼ)
	CommitmentID map[party.ID]hash.Commitment
	// DecommitmentID is the decommitment string for idᵢ
	DecommitmentID hash.Decommitment
}

type broadcast2 struct {
	// K = Kᵢ
	K *paillier.Ciphertext
	// G = Gᵢ
	G *paillier.Ciphertext
	// Z = Zᵢ
	Z *elgamal.Ciphertext
	// CommitmentID is a commitment Pᵢ's contribution to the final presignature ID.
	CommitmentID hash.Commitment
}

type message2 struct {
	broadcast2
	Proof *zkencelg.Proof
}

// VerifyMessage implements round.Round.
//
// - verify zkencelg.
func (r *presign2) VerifyMessage(msg round.Message) error {
	from, to := msg.From, msg.To
	body, ok := msg.Content.(*message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if !r.Paillier[from].ValidateCiphertexts(body.K, body.G) || !body.Z.Valid() || body.Proof == nil {
		return round.ErrNilFields
	}

	if err := body.CommitmentID.Validate(); err != nil {
		return err
	}

	if !body.Proof.Verify(r.HashForID(from), zkencelg.Public{
		C:      body.K,
		A:      r.ElGamal[from],
		B:      body.Z.L,
		X:      body.Z.M,
		Prover: r.Paillier[from],
		Aux:    r.Pedersen[to],
	}) {
		return errors.New("failed to validate enc-elg proof for K")
	}
	return nil
}

// StoreMessage implements round.Round.
//
// - store Kⱼ, Gⱼ, Zⱼ.
func (r *presign2) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(*message2)
	r.K[from] = body.K
	r.G[from] = body.G
	r.ElGamalK[from] = body.Z
	r.CommitmentID[from] = body.CommitmentID
	return nil
}

// Finalize implements round.Round
//
// Compute MtA for χᵢ, δᵢ
func (r *presign2) Finalize(out chan<- *round.Message) (round.Round, error) {
	otherIDs := r.OtherPartyIDs()
	n := len(otherIDs)

	type mtaOut struct {
		DeltaBeta  *safenum.Int
		DeltaD     *paillier.Ciphertext
		DeltaF     *paillier.Ciphertext
		DeltaProof *zkaffp.Proof
		ChiBeta    *safenum.Int
		ChiD       *paillier.Ciphertext
		ChiF       *paillier.Ciphertext
		ChiProof   *zkaffg.Proof
	}
	mtaOuts := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]

		DeltaBeta, DeltaD, DeltaF, DeltaProof := mta.ProveAffP(r.HashForID(r.SelfID()),
			r.GammaShare, r.G[r.SelfID()], r.GNonce, r.K[j],
			r.SecretPaillier, r.Paillier[j], r.Pedersen[j])

		ChiBeta, ChiD, ChiF, ChiProof := mta.ProveAffG(r.Group(), r.HashForID(r.SelfID()),
			curve.MakeInt(r.SecretECDSA), r.ECDSA[r.SelfID()], r.K[j],
			r.SecretPaillier, r.Paillier[j], r.Pedersen[j])

		return mtaOut{
			DeltaBeta:  DeltaBeta,
			DeltaD:     DeltaD,
			DeltaF:     DeltaF,
			DeltaProof: DeltaProof,
			ChiBeta:    ChiBeta,
			ChiD:       ChiD,
			ChiF:       ChiF,
			ChiProof:   ChiProof,
		}
	})
	ChiCiphertext := make(map[party.ID]*paillier.Ciphertext, n)
	DeltaCiphertext := make(map[party.ID]*paillier.Ciphertext, n)
	DeltaShareBeta := make(map[party.ID]*safenum.Int, n)
	ChiShareBeta := make(map[party.ID]*safenum.Int, n)

	broadcastMsg := broadcast3{
		DeltaCiphertext: DeltaCiphertext,
		ChiCiphertext:   ChiCiphertext,
	}

	msgs := make(map[party.ID]*message3, n)
	for idx, mtaOutRaw := range mtaOuts {
		j := otherIDs[idx]
		m := mtaOutRaw.(mtaOut)
		DeltaShareBeta[j] = m.DeltaBeta
		DeltaCiphertext[j] = m.DeltaD
		ChiShareBeta[j] = m.ChiBeta
		ChiCiphertext[j] = m.ChiD
		msgs[j] = &message3{
			broadcast3: broadcastMsg,
			DeltaF:     m.DeltaF,
			DeltaProof: m.DeltaProof,
			ChiF:       m.ChiF,
			ChiProof:   m.ChiProof,
		}
	}

	for id, msg := range msgs {
		if err := r.SendMessage(out, msg, id); err != nil {
			return r, err
		}
	}

	return broadcast.New(r.Helper, &presign3{
		presign2:        r,
		DeltaShareBeta:  DeltaShareBeta,
		ChiShareBeta:    ChiShareBeta,
		DeltaShareAlpha: map[party.ID]*safenum.Int{},
		ChiShareAlpha:   map[party.ID]*safenum.Int{},
		DeltaCiphertext: map[party.ID]map[party.ID]*paillier.Ciphertext{r.SelfID(): DeltaCiphertext},
		ChiCiphertext:   map[party.ID]map[party.ID]*paillier.Ciphertext{r.SelfID(): ChiCiphertext},
	}, broadcastMsg), nil
}

// MessageContent implements round.Round.
func (presign2) MessageContent() round.Content { return &message2{} }

// Number implements round.Round.
func (presign2) Number() round.Number { return 2 }

// Init implements round.Content.
func (m *message2) Init(group curve.Curve) {
	m.Z = elgamal.Empty(group)
	m.Proof = zkencelg.Empty(group)
}

// BroadcastData implements broadcast.Broadcaster.
func (m broadcast2) BroadcastData() []byte {
	return hash.New(m.K, m.G, m.Z, m.CommitmentID).Sum()
}
