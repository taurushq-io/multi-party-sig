package presign

import (
	"crypto/rand"

	"github.com/taurusgroup/multi-party-sig/internal/elgamal"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	zkencelg "github.com/taurusgroup/multi-party-sig/pkg/zk/encelg"
)

var _ round.Round = (*presign1)(nil)

type presign1 struct {
	*round.Helper

	// Pool allows us to parallelize certain operations
	Pool *pool.Pool

	// SecretECDSA = xᵢ
	SecretECDSA curve.Scalar
	// SecretElGamal = yᵢ
	SecretElGamal curve.Scalar
	// SecretPaillier = (pᵢ, qᵢ)
	SecretPaillier *paillier.SecretKey

	// PublicKey = X
	PublicKey curve.Point
	// ECDSA[j] = Xⱼ
	ECDSA map[party.ID]curve.Point
	// ElGamal[j] = Yⱼ
	ElGamal map[party.ID]curve.Point
	// Paillier[j] = Nⱼ
	Paillier map[party.ID]*paillier.PublicKey
	// Pedersen[j] = (Nⱼ,Sⱼ,Tⱼ)
	Pedersen map[party.ID]*pedersen.Parameters

	// Message is the message to be signed. If it is nil, a presignature is created.
	Message []byte
}

// VerifyMessage implements round.Round.
func (presign1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (presign1) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - sample kᵢ, γᵢ <- 𝔽,
// - Γᵢ = [γᵢ]⋅G
// - Gᵢ = Encᵢ(γᵢ;νᵢ)
// - Kᵢ = Encᵢ(kᵢ;ρᵢ)
//
// NOTE
// The protocol instructs us to broadcast Kᵢ and Gᵢ, but the protocol we implement
// cannot handle identify aborts since we are in a point to point model.
// We do as described in [LN18].
//
// In the next round, we send a hash of all the {Kⱼ,Gⱼ}ⱼ.
// In two rounds, we compare the hashes received and if they are different then we abort.
func (r *presign1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// γᵢ <- 𝔽,
	GammaShare := sample.Scalar(rand.Reader, r.Group())
	// Gᵢ = Encᵢ(γᵢ;νᵢ)
	G, GNonce := r.Paillier[r.SelfID()].Enc(curve.MakeInt(GammaShare))

	// kᵢ <- 𝔽,
	KShare := sample.Scalar(rand.Reader, r.Group())
	KShareInt := curve.MakeInt(KShare)
	// Kᵢ = Encᵢ(kᵢ;ρᵢ)
	K, KNonce := r.Paillier[r.SelfID()].Enc(KShareInt)

	// Zᵢ = (bᵢ⋅G, kᵢ⋅G+bᵢ⋅Yᵢ), bᵢ
	ElGamalK, ElGamalNonce := elgamal.Encrypt(r.ElGamal[r.SelfID()], KShare)

	presignatureID, err := types.NewRID(rand.Reader)
	if err != nil {
		return r, err
	}
	commitmentID, decommitmentID, err := r.HashForID(r.SelfID()).Commit(presignatureID)
	if err != nil {
		return r, err
	}

	otherIDs := r.OtherPartyIDs()
	broadcastMsg := broadcast2{
		K:            K,
		G:            G,
		Z:            ElGamalK,
		CommitmentID: commitmentID,
	}
	if err = r.BroadcastMessage(out, &broadcastMsg); err != nil {
		return r, err
	}
	errs := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]
		proof := zkencelg.NewProof(r.Group(), r.HashForID(r.SelfID()), zkencelg.Public{
			C:      K,
			A:      r.ElGamal[r.SelfID()],
			B:      ElGamalK.L,
			X:      ElGamalK.M,
			Prover: r.Paillier[r.SelfID()],
			Aux:    r.Pedersen[j],
		}, zkencelg.Private{
			X:   KShareInt,
			Rho: KNonce,
			A:   r.SecretElGamal,
			B:   ElGamalNonce,
		})

		return r.SendMessage(out, &message2{Proof: proof}, j)
	})
	for _, err := range errs {
		if err != nil {
			return r, err.(error)
		}
	}

	return &presign2{
		presign1:       r,
		K:              map[party.ID]*paillier.Ciphertext{r.SelfID(): K},
		G:              map[party.ID]*paillier.Ciphertext{r.SelfID(): G},
		GammaShare:     curve.MakeInt(GammaShare),
		KShare:         KShare,
		KNonce:         KNonce,
		GNonce:         GNonce,
		ElGamalKNonce:  ElGamalNonce,
		ElGamalK:       map[party.ID]*elgamal.Ciphertext{r.SelfID(): ElGamalK},
		PresignatureID: map[party.ID]types.RID{r.SelfID(): presignatureID},
		CommitmentID:   map[party.ID]hash.Commitment{},
		DecommitmentID: decommitmentID,
	}, nil
}

// MessageContent implements round.Round.
func (presign1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (presign1) Number() round.Number { return 1 }
