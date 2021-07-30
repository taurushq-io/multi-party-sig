package keygen

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/cmp-ecdsa/internal/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
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

	// ShareReceived[j] = xʲᵢ
	// share received from party j
	ShareReceived map[party.ID]*curve.Scalar

	// PaillierPublic[j] = Nⱼ
	PaillierPublic map[party.ID]*paillier.PublicKey

	// N[j], S[j], T[j]  = Nⱼ, sⱼ, tⱼ
	N, S, T map[party.ID]*big.Int

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

// ProcessMessage implements round.Round.
//
// - store commitment Vⱼ.
func (r *round2) ProcessMessage(j party.ID, content message.Content) error {
	body := content.(*Keygen2)
	r.Commitments[j] = body.Commitment
	return nil
}

// Finalize implements round.Round
//
// Since we assume a simple P2P network, we use an extra round to "echo"
// the hash. Everybody sends a hash of all hashes.
//
// - send Hash(ssid, V₁, …, Vₙ).
func (r *round2) Finalize(out chan<- *message.Message) (round.Round, error) {
	// Broadcast the message we created in round1
	h := r.Hash()
	for _, j := range r.PartyIDs() {
		_, _ = h.WriteAny(r.Commitments[j])
	}
	EchoHash := h.ReadBytes(nil)

	// send to all
	msg := r.MarshalMessage(&Keygen3{HashEcho: EchoHash}, r.OtherPartyIDs()...)
	if err := r.SendMessage(msg, out); err != nil {
		return r, err
	}

	return &round3{
		round2:   r,
		EchoHash: EchoHash,
	}, nil
}

// MessageContent implements round.Round.
func (r *round2) MessageContent() message.Content { return &Keygen2{} }

// Validate implements message.Content.
func (m *Keygen2) Validate() error {
	if m == nil {
		return errors.New("keygen.round1: message is nil")
	}
	if err := m.Commitment.Validate(); err != nil {
		return fmt.Errorf("keygen.round1: %w", err)
	}
	return nil
}

// RoundNumber implements message.Content.
func (m *Keygen2) RoundNumber() types.RoundNumber { return 2 }
