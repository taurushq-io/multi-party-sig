package sign

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
	zkenc "github.com/taurusgroup/cmp-ecdsa/pkg/zk/enc"
	zklogstar "github.com/taurusgroup/cmp-ecdsa/pkg/zk/logstar"
)

type round2 struct {
	*round1

	// EchoHash = Hash(ssid, K₁, G₁, …, Kₙ, Gₙ)
	// part of the echo of the first message
	EchoHash []byte
}

// ProcessMessage implements round.Round
//
// - store Kⱼ, Gⱼ
// - verify zkenc(Kⱼ)
func (r *round2) ProcessMessage(j party.ID, content message.Content) error {
	body := content.(*Sign2)
	partyJ := r.Parties[j]

	if !body.ProofEnc.Verify(r.HashForID(j), zkenc.Public{
		K:      body.K,
		Prover: partyJ.Public.Paillier,
		Aux:    r.Self.Public.Pedersen,
	}) {
		return ErrRound2ZKEnc
	}

	partyJ.K = body.K
	partyJ.G = body.G
	return nil
}

// Finalize implements round.Round
//
// - compute Hash(ssid, K₁, G₁, …, Kₙ, Gₙ)
func (r *round2) Finalize(out chan<- *message.Message) (round.Round, error) {
	// compute Hash(ssid, K₁, G₁, …, Kₙ, Gₙ)
	// The papers says that we need to reliably broadcast this data, however unless we use
	// a system like white-city, we can't actually do this.
	// In the next round, if someone has a different hash, then we must abort, but there is no way of knowing who
	// was the culprit. We could maybe assume that we have an honest majority, but this clashes with the base assumptions.
	h := r.Hash()
	for _, id := range r.PartyIDs() {
		partyJ := r.Parties[id]
		_, _ = h.WriteAny(partyJ.K, partyJ.G)
	}
	r.EchoHash = h.ReadBytes(nil)

	zkPrivate := zklogstar.Private{
		X:   r.GammaShare.Int(),
		Rho: r.GNonce,
	}

	// Broadcast the message we created in round1
	for j, partyJ := range r.Parties {
		if j == r.SelfID() {
			continue
		}

		partyJ.DeltaMtA = NewMtA(r.GammaShare, r.Self.BigGammaShare, partyJ.K,
			r.Self.Public, partyJ.Public)
		partyJ.ChiMtA = NewMtA(r.Secret.ECDSA, r.Self.ECDSA, partyJ.K,
			r.Self.Public, partyJ.Public)

		proofLog := zklogstar.NewProof(r.HashForID(r.SelfID()), zklogstar.Public{
			C:      r.Self.G,
			X:      r.Self.BigGammaShare,
			Prover: r.Self.Paillier,
			Aux:    partyJ.Pedersen,
		}, zkPrivate)

		msg := r.MarshalMessage(&Sign3{
			EchoHash:      r.EchoHash,
			BigGammaShare: r.Self.BigGammaShare,
			DeltaMtA:      partyJ.DeltaMtA.ProofAffG(r.HashForID(r.SelfID()), nil),
			ChiMtA:        partyJ.ChiMtA.ProofAffG(r.HashForID(r.SelfID()), nil),
			ProofLog:      proofLog,
		}, j)
		if err := r.SendMessage(msg, out); err != nil {
			return r, err
		}
	}

	return &round3{round2: r}, nil
}

// MessageContent implements round.Round
func (r *round2) MessageContent() message.Content { return &Sign2{} }

// Validate implements message.Content
func (m *Sign2) Validate() error {
	if m == nil {
		return errors.New("sign.round1: message is nil")
	}
	if m.G == nil || m.K == nil {
		return errors.New("sign.round1: K or G is nil")
	}
	return nil
}

// RoundNumber implements message.Content
func (m *Sign2) RoundNumber() types.RoundNumber { return 2 }
