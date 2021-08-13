package keygen

import (
	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/message"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/types"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
)

var _ round.Round = (*round2)(nil)

type round2 struct {
	*round1

	// VSSPolynomials[j] = Fⱼ(X) = fⱼ(X)•G
	VSSPolynomials map[party.ID]*polynomial.Exponent

	// Commitments[j] = H(Keygen3ⱼ ∥ Decommitments[j])
	Commitments map[party.ID]hash.Commitment

	// RIDs[j] = ridⱼ
	RIDs map[party.ID]RID
	// ChainKeys[j] = cⱼ
	ChainKeys map[party.ID]RID

	// ShareReceived[j] = xʲᵢ
	// share received from party j
	ShareReceived map[party.ID]curve.Scalar

	// PaillierPublic[j] = Nⱼ
	PaillierPublic map[party.ID]*paillier.PublicKey

	// N[j] = Nⱼ
	N map[party.ID]*safenum.Modulus
	// S[j], T[j] = sⱼ, tⱼ
	S, T map[party.ID]*safenum.Nat

	// PaillierSecret = (pᵢ, qᵢ)
	PaillierSecret *paillier.SecretKey

	// PedersenSecret = λᵢ
	// Used to generate the Pedersen parameters
	PedersenSecret *safenum.Nat

	// SchnorrRand = aᵢ
	// Randomness used to compute Schnorr commitment of proof of knowledge of secret share
	SchnorrRand *zksch.Randomness

	// Decommitment for Keygen3ᵢ
	Decommitment hash.Decommitment // uᵢ
}

type Keygen2 struct {
	// Commitment = Vᵢ = H(ρᵢ, Fᵢ(X), Aᵢ, Nᵢ, sᵢ, tᵢ, uᵢ)
	Commitment hash.Commitment
}

// VerifyMessage implements round.Round.
func (r *round2) VerifyMessage(_ party.ID, _ party.ID, content message.Content) error {
	body, ok := content.(*Keygen2)
	if !ok || body == nil {
		return message.ErrInvalidContent
	}
	if err := body.Commitment.Validate(); err != nil {
		return err
	}
	return nil
}

// StoreMessage implements round.Round.
//
// - save commitment Vⱼ.
func (r *round2) StoreMessage(from party.ID, content message.Content) error {
	body := content.(*Keygen2)
	r.Commitments[from] = body.Commitment
	return nil
}

// Finalize implements round.Round
//
// Since we assume a simple P2P network, we use an extra round to "echo"
// the hash. Everybody sends a hash of all hashes.
//
// - send all committed data.
// - send Hash(ssid, V₁, …, Vₙ).
func (r *round2) Finalize(out chan<- *message.Message) (round.Round, error) {
	// Broadcast the message we created in Round1
	h := r.Hash()
	for _, j := range r.PartyIDs() {
		_ = h.WriteAny(r.Commitments[j])
	}
	EchoHash := h.Sum()

	// Send the message we created in Round1 to all
	msg := r.MarshalMessage(&Keygen3{
		RID:                r.RIDs[r.SelfID()],
		C:                  r.ChainKeys[r.SelfID()],
		VSSPolynomial:      r.VSSPolynomials[r.SelfID()],
		SchnorrCommitments: r.SchnorrRand.Commitment(),
		N:                  r.N[r.SelfID()],
		S:                  r.S[r.SelfID()],
		T:                  r.T[r.SelfID()],
		Decommitment:       r.Decommitment,
		HashEcho:           EchoHash,
	}, r.OtherPartyIDs()...)
	if err := r.SendMessage(msg, out); err != nil {
		return r, err
	}
	return &round3{
		round2:             r,
		EchoHash:           EchoHash,
		SchnorrCommitments: map[party.ID]*zksch.Commitment{},
	}, nil
}

// MessageContent implements round.Round.
func (round2) MessageContent() message.Content { return &Keygen2{} }

// RoundNumber implements message.Content.
func (Keygen2) RoundNumber() types.RoundNumber { return 2 }
