package presign

import (
	"github.com/taurusgroup/multi-party-sig/internal/elgamal"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	zklogstar "github.com/taurusgroup/multi-party-sig/pkg/zk/logstar"
)

var _ round.Round = (*presign4)(nil)

type presign4 struct {
	*presign3

	// ElGamalChiNonce = b̂ᵢ
	ElGamalChiNonce elgamal.Nonce
	// ElGamalChi[j] = Ẑⱼ = (b̂ⱼ, χⱼ⋅G+b̂ⱼ⋅Yⱼ)
	ElGamalChi map[party.ID]*elgamal.Ciphertext

	// DeltaShares[j] = δⱼ
	DeltaShares map[party.ID]curve.Scalar

	// ChiShare = χᵢ
	ChiShare curve.Scalar
}

type message4 struct {
	// DeltaShare = δⱼ
	DeltaShare curve.Scalar
	// ElGamalChi = Ẑᵢ = (b̂ᵢ, χᵢ⋅G+b̂ᵢ⋅Yᵢ)
	ElGamalChi *elgamal.Ciphertext
}

// VerifyMessage implements round.Round.
func (r *presign4) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message4)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.DeltaShare.IsZero() || !body.ElGamalChi.Valid() {
		return round.ErrNilFields
	}

	return nil
}

// StoreMessage implements round.Round.
//
// - store Ẑⱼ, δⱼ.
func (r *presign4) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(*message4)
	r.ElGamalChi[from] = body.ElGamalChi
	r.DeltaShares[from] = body.DeltaShare
	return nil
}

// Finalize implements round.Round
//
// - set Γᵢ = γᵢ⋅G.
// - prove zklogstar.
func (r *presign4) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Γᵢ = γᵢ⋅G
	BigGammaShare := r.Group().NewScalar().SetNat(r.GammaShare.Mod(r.Group().Order())).ActOnBase()

	zkPrivate := zklogstar.Private{
		X:   r.GammaShare,
		Rho: r.GNonce,
	}

	otherIDs := r.OtherPartyIDs()
	errors := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]

		proofLog := zklogstar.NewProof(r.Group(), r.HashForID(r.SelfID()), zklogstar.Public{
			C:      r.G[r.SelfID()],
			X:      BigGammaShare,
			Prover: r.Paillier[r.SelfID()],
			Aux:    r.Pedersen[j],
		}, zkPrivate)

		err := r.SendMessage(out, &message5{
			BigGammaShare: BigGammaShare,
			ProofLog:      proofLog,
		}, j)
		if err != nil {
			return err
		}

		return nil
	})
	for _, err := range errors {
		if err != nil {
			return r, err.(error)
		}
	}

	return &presign5{
		presign4:      r,
		BigGammaShare: map[party.ID]curve.Point{r.SelfID(): BigGammaShare},
	}, nil
}

// MessageContent implements round.Round.
func (presign4) MessageContent() round.Content { return &message4{} }

// Number implements round.Round.
func (presign4) Number() round.Number { return 4 }

// Init implements round.Content.
func (m *message4) Init(group curve.Curve) {
	m.DeltaShare = group.NewScalar()
	m.ElGamalChi = elgamal.Empty(group)
}
