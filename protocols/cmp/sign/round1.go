package sign

import (
	"crypto/rand"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
	zkenc "github.com/taurusgroup/multi-party-sig/pkg/zk/enc"
)

var _ round.Round = (*round1)(nil)

type round1 struct {
	*round.Helper

	PublicKey curve.Point

	SecretECDSA    curve.Scalar
	SecretPaillier *paillier.SecretKey
	Paillier       map[party.ID]*paillier.PublicKey
	Pedersen       map[party.ID]*pedersen.Parameters
	ECDSA          map[party.ID]curve.Point

	Message []byte
}

// VerifyMessage implements round.Round.
func (round1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round1) StoreMessage(round.Message) error { return nil }

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
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// γᵢ <- 𝔽,
	// Γᵢ = [γᵢ]⋅G
	GammaShare, BigGammaShare := sample.ScalarPointPair(rand.Reader, r.Group())
	// Gᵢ = Encᵢ(γᵢ;νᵢ)
	G, GNonce := r.Paillier[r.SelfID()].Enc(curve.MakeInt(GammaShare))

	// kᵢ <- 𝔽,
	KShare := sample.Scalar(rand.Reader, r.Group())
	// Kᵢ = Encᵢ(kᵢ;ρᵢ)
	K, KNonce := r.Paillier[r.SelfID()].Enc(curve.MakeInt(KShare))

	otherIDs := r.OtherPartyIDs()
	broadcastMsg := broadcast2{K: K, G: G}
	if err := r.BroadcastMessage(out, &broadcastMsg); err != nil {
		return r, err
	}
	errors := r.Pool.Parallelize(len(otherIDs), func(i int) interface{} {
		j := otherIDs[i]
		proof := zkenc.NewProof(r.Group(), r.HashForID(r.SelfID()), zkenc.Public{
			K:      K,
			Prover: r.Paillier[r.SelfID()],
			Aux:    r.Pedersen[j],
		}, zkenc.Private{
			K:   curve.MakeInt(KShare),
			Rho: KNonce,
		})

		err := r.SendMessage(out, &message2{
			ProofEnc: proof,
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

	return &round2{
		round1:        r,
		K:             map[party.ID]*paillier.Ciphertext{r.SelfID(): K},
		G:             map[party.ID]*paillier.Ciphertext{r.SelfID(): G},
		BigGammaShare: map[party.ID]curve.Point{r.SelfID(): BigGammaShare},
		GammaShare:    curve.MakeInt(GammaShare),
		KShare:        KShare,
		KNonce:        KNonce,
		GNonce:        GNonce,
	}, nil
}

// MessageContent implements round.Round.
func (round1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round1) Number() round.Number { return 1 }
