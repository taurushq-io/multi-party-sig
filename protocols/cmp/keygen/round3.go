package keygen

import (
	"bytes"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/hash"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/message"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/types"
	zkmod "github.com/taurusgroup/multi-party-sig/pkg/zk/mod"
	zkprm "github.com/taurusgroup/multi-party-sig/pkg/zk/prm"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
)

var _ round.Round = (*round3)(nil)

type round3 struct {
	*round2
	// EchoHash = Hash(SSID, commitment₁, …, commitmentₙ)
	EchoHash []byte

	// SchnorrCommitments[j] = Aⱼ
	// Commitment for proof of knowledge in the last round
	SchnorrCommitments map[party.ID]*zksch.Commitment // Aⱼ
}

type Keygen3 struct {
	// RID = RIDᵢ
	RID RID
	C   RID
	// VSSPolynomial = Fᵢ(X) VSSPolynomial
	VSSPolynomial *polynomial.Exponent
	// SchnorrCommitments = Aᵢ Schnorr commitment for the final confirmation
	SchnorrCommitments *zksch.Commitment
	// N Paillier and Pedersen N = p•q, p ≡ q ≡ 3 mod 4
	N *safenum.Modulus
	// S = r² mod N
	S *safenum.Nat
	// T = Sˡ mod N
	T *safenum.Nat
	// Decommitment = uᵢ decommitment bytes
	Decommitment hash.Decommitment
	// HashEcho = H(V₁, …, Vₙ)
	// This is essentially an echo of all Message2 from Round1.
	// If one party received something different then everybody must abort.
	HashEcho []byte
}

// VerifyMessage implements round.Round.
//
// - verify Hash(SSID, V₁, …, Vₙ) against received hash.
// - verify length of Schnorr commitments
// - verify degree of VSS polynomial Fⱼ "in-the-exponent"
//   - if keygen, verify Fⱼ(0) != ∞
//   - if refresh, verify Fⱼ(0) == ∞
// - validate Paillier
// - validate Pedersen
// - validate commitments.
func (r *round3) VerifyMessage(from party.ID, _ party.ID, content message.Content) error {
	body, ok := content.(*Keygen3)
	if !ok || body == nil {
		return message.ErrInvalidContent
	}

	// check nil
	if body.N == nil || body.S == nil || body.T == nil || body.VSSPolynomial == nil {
		return message.ErrNilFields
	}
	// check RID length
	if err := body.RID.Validate(); err != nil {
		return err
	}
	// check decommitment
	if err := body.Decommitment.Validate(); err != nil {
		return err
	}
	// check echo hash
	if !bytes.Equal(body.HashEcho, r.EchoHash) {
		return ErrRound3EchoHash
	}

	// Save all X, VSSCommitments
	VSSPolynomial := body.VSSPolynomial
	// check that the constant coefficient is 0
	// if refresh then the polynomial is constant
	if !(r.VSSSecret.Constant().IsZero() == VSSPolynomial.IsConstant) {
		return ErrRound3VSSConstant
	}
	// check deg(Fⱼ) = t
	if VSSPolynomial.Degree() != r.Threshold {
		return ErrRound3VSSDegree
	}

	// Set Paillier
	if err := paillier.ValidateN(body.N); err != nil {
		return err
	}

	// Verify Pedersen
	if err := pedersen.ValidateParameters(body.N, body.S, body.T); err != nil {
		return err
	}
	// Verify decommit
	if !r.HashForID(from).Decommit(r.Commitments[from], body.Decommitment,
		body.RID, body.C, VSSPolynomial, body.SchnorrCommitments, body.N, body.S, body.T) {
		return ErrRound3Decommit
	}

	return nil
}

// StoreMessage implements round.Round.
// - store ridⱼ, Cⱼ, Nⱼ, Sⱼ, Tⱼ, Fⱼ(X), Aⱼ.
func (r *round3) StoreMessage(from party.ID, content message.Content) error {
	body := content.(*Keygen3)
	r.RIDs[from] = body.RID
	r.ChainKeys[from] = body.RID
	r.N[from] = body.N
	r.S[from] = body.S
	r.T[from] = body.T
	r.PaillierPublic[from] = paillier.NewPublicKey(body.N)
	r.VSSPolynomials[from] = body.VSSPolynomial
	r.SchnorrCommitments[from] = body.SchnorrCommitments
	return nil
}

// Finalize implements round.Round
//
// - set rid = ⊕ⱼ ridⱼ and update hash state
// - prove Nᵢ is Blum
// - prove Pedersen parameters
// - prove Schnorr for all coefficients of fᵢ(X)
//   - if refresh skip constant coefficient
//
// - send proofs and encryption of share for Pⱼ.
func (r *round3) Finalize(out chan<- *message.Message) (round.Round, error) {
	// RID = ⊕ⱼ RIDⱼ
	// c = ⊕ⱼ cⱼ
	rid := newRID()
	chainKey := r.PreviousChainKey
	if chainKey == nil {
		chainKeyRID := newRID()
		for _, j := range r.PartyIDs() {
			rid.XOR(r.RIDs[j])
			chainKeyRID.XOR(r.ChainKeys[j])
		}
		chainKey = chainKeyRID
	}
	// temporary hash which does not modify the state
	h := r.Hash()
	_ = h.WriteAny(rid, r.SelfID())

	// Prove N is a blum prime with zkmod
	mod := zkmod.NewProof(r.Pool, h.Clone(), zkmod.Public{N: r.N[r.SelfID()]}, zkmod.Private{
		P:   r.PaillierSecret.P(),
		Q:   r.PaillierSecret.Q(),
		Phi: r.PaillierSecret.Phi(),
	})

	// prove s, t are correct as aux parameters with zkprm
	prm := zkprm.NewProof(r.Pool, h.Clone(), zkprm.Public{N: r.N[r.SelfID()], S: r.S[r.SelfID()], T: r.T[r.SelfID()]}, zkprm.Private{
		Lambda: r.PedersenSecret,
		Phi:    r.PaillierSecret.Phi(),
		P:      r.PaillierSecret.P(),
		Q:      r.PaillierSecret.Q(),
	})

	// create messages with encrypted shares
	for _, j := range r.OtherPartyIDs() {
		// compute fᵢ(j)
		share := r.VSSSecret.Evaluate(j.Scalar(r.Group()))
		// Encrypt share
		C, _ := r.PaillierPublic[j].Enc(share.Int())

		msg := r.MarshalMessage(&Keygen4{
			Mod:   mod,
			Prm:   prm,
			Share: C,
		}, j)
		if err := r.SendMessage(msg, out); err != nil {
			return r, err
		}
	}

	// Write rid to the hash state
	r.UpdateHashState(rid)
	return &round4{
		round3:   r,
		RID:      rid,
		ChainKey: chainKey,
	}, nil
}

// MessageContent implements round.Round.
func (r *round3) MessageContent() message.Content {
	return &Keygen3{
		VSSPolynomial:      polynomial.EmptyExponent(r.Group()),
		SchnorrCommitments: zksch.EmptyCommitment(r.Group()),
	}
}

// RoundNumber implements message.Content.
func (Keygen3) RoundNumber() types.RoundNumber { return 4 }
