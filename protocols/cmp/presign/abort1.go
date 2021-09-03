package presign

import (
	"errors"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/arith"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	zknth "github.com/taurusgroup/multi-party-sig/pkg/zk/nth"
)

var _ round.Round = (*abort1)(nil)

type abort1 struct {
	*presign6
	GammaShares map[party.ID]*safenum.Int
	KShares     map[party.ID]*safenum.Int
	// DeltaAlphas[j][k] = αⱼₖ
	DeltaAlphas map[party.ID]map[party.ID]*safenum.Int
}

type broadcastAbort1 struct {
	round.NormalBroadcastContent
	// GammaShare = γᵢ
	GammaShare  *safenum.Int
	KProof      *abortNth
	DeltaProofs map[party.ID]*abortNth
}

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *abort1) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcastAbort1)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	alphas := make(map[party.ID]*safenum.Int, len(body.DeltaProofs))
	for id, deltaProof := range body.DeltaProofs {
		alphas[id] = deltaProof.Plaintext
	}
	r.DeltaAlphas[from] = alphas
	r.GammaShares[from] = body.GammaShare
	r.KShares[from] = body.KProof.Plaintext

	public := r.Paillier[from]
	if !body.KProof.Verify(r.HashForID(from), public, r.K[from]) {
		return errors.New("failed to verify validity of k")
	}

	BigGammaShareActual := r.Group().NewScalar().SetNat(body.GammaShare.Mod(r.Group().Order())).ActOnBase()
	if !r.BigGammaShare[from].Equal(BigGammaShareActual) {
		return errors.New("different BigGammaShare")
	}

	for id, deltaProof := range body.DeltaProofs {
		if !deltaProof.Verify(r.HashForID(from), public, r.DeltaCiphertext[from][id]) {
			return errors.New("failed to validate Delta MtA Nth proof")
		}
	}
	return nil
}

// VerifyMessage implements round.Round.
func (abort1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (abort1) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
func (r *abort1) Finalize(chan<- *round.Message) (round.Session, error) {
	var (
		culprits   []party.ID
		delta, tmp safenum.Int
	)
	for _, j := range r.OtherPartyIDs() {
		delta.Mul(r.KShares[j], r.GammaShares[j], -1)
		for _, l := range r.PartyIDs() {
			if l == j {
				continue
			}
			delta.Add(&delta, r.DeltaAlphas[j][l], -1)
			tmp.Mul(r.KShares[l], r.GammaShares[j], -1)
			delta.Add(&delta, &tmp, -1)
			tmp.SetInt(r.DeltaAlphas[l][j]).Neg(1)
			delta.Add(&delta, &tmp, -1)
		}
		deltaScalar := r.Group().NewScalar().SetNat(delta.Mod(r.Group().Order()))
		if !deltaScalar.Equal(r.DeltaShares[j]) {
			culprits = append(culprits, j)
		}
	}
	return r.AbortRound(errors.New("abort1: detected culprit"), culprits...), nil
}

// MessageContent implements round.Round.
func (abort1) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcastAbort1) RoundNumber() round.Number { return 7 }

// BroadcastContent implements round.BroadcastRound.
func (r *abort1) BroadcastContent() round.BroadcastContent { return &broadcastAbort1{} }

// Number implements round.Round.
func (abort1) Number() round.Number { return 7 }

type abortNth struct {
	Plaintext *safenum.Int
	Nonce     *safenum.Nat
	Proof     *zknth.Proof
}

func proveNth(hash *hash.Hash, paillierSecret *paillier.SecretKey, c *paillier.Ciphertext) *abortNth {
	NSquared := paillierSecret.ModulusSquared()
	N := paillierSecret.Modulus()
	deltaShareAlpha, deltaNonce, _ := paillierSecret.DecWithRandomness(c)
	deltaNonceHidden := NSquared.Exp(deltaNonce, N.Nat())
	proof := zknth.NewProof(hash, zknth.Public{
		N: paillierSecret.PublicKey,
		R: deltaNonceHidden,
	}, zknth.Private{Rho: deltaNonce})
	return &abortNth{
		Plaintext: deltaShareAlpha,
		Nonce:     deltaNonceHidden,
		Proof:     proof,
	}
}

func (msg *abortNth) Verify(hash *hash.Hash, paillierPublic *paillier.PublicKey, c *paillier.Ciphertext) bool {
	if msg == nil || !arith.IsValidNatModN(paillierPublic.N(), msg.Nonce) || msg.Plaintext == nil {
		return false
	}
	one := new(safenum.Nat).SetUint64(1)
	cExpected := c.Nat()
	cActual := paillierPublic.EncWithNonce(msg.Plaintext, one).Nat()
	cActual.ModMul(cActual, msg.Nonce, paillierPublic.ModulusSquared().Modulus)
	if cExpected.Eq(cActual) != 1 {
		return false
	}
	if !msg.Proof.Verify(hash, zknth.Public{
		N: paillierPublic,
		R: msg.Nonce,
	}) {
		return false
	}
	return true
}
