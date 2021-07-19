package sign

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
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
func (r *round2) ProcessMessage(msg round.Message) error {
	j := msg.GetHeader().From
	partyJ := r.parties[j]
	body := msg.(*Message).GetSign1()

	if !body.ProofEnc.Verify(r.Hash.CloneWithID(j), zkenc.Public{
		K:      body.K,
		Prover: partyJ.Public.Paillier,
		Aux:    r.Self.Public.Pedersen,
	}) {
		return fmt.Errorf("sign.round2.ProcessMessage(): party %s: enc proof failed to verify", j)
	}

	partyJ.K = body.K
	partyJ.G = body.G

	return nil // message is properly handled
}

// GenerateMessages implements round.Round
//
// - compute Hash(ssid, K₁, G₁, …, Kₙ, Gₙ)
func (r *round2) GenerateMessages() ([]round.Message, error) {
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
		X:   r.GammaShare.BigInt(),
		Rho: r.GNonce,
	}
	// Broadcast the message we created in round1
	messages := make([]round.Message, 0, r.S.N()-1)
	for j, partyJ := range r.parties {
		if j == r.SelfID {
			continue
		}

		partyJ.DeltaMtA = NewMtA(r.GammaShare, r.Self.BigGammaShare, partyJ.K,
			r.Self.Public, partyJ.Public)
		partyJ.ChiMtA = NewMtA(r.Secret.ECDSA, r.Self.ECDSA, partyJ.K,
			r.Self.Public, partyJ.Public)

		proofLog := zklogstar.NewProof(r.Hash.CloneWithID(r.SelfID), zklogstar.Public{
			C:      r.Self.G,
			X:      r.Self.BigGammaShare,
			Prover: r.Self.Paillier,
			Aux:    partyJ.Pedersen,
		}, zkPrivate)

		sign2 := &Sign2{
			EchoHash:      r.EchoHash,
			BigGammaShare: r.Self.BigGammaShare,
			DeltaMtA:      partyJ.DeltaMtA.ProofAffG(r.Hash.CloneWithID(r.SelfID), nil),
			ChiMtA:        partyJ.ChiMtA.ProofAffG(r.Hash.CloneWithID(r.SelfID), nil),
			ProofLog:      proofLog,
		}

		messages = append(messages, NewMessageSign2(r.SelfID, partyJ.ID, sign2))
	}

	return messages, nil
}

// Next implements round.Round
func (r *round2) Next() round.Round {
	return &round3{
		round2: r,
	}
}

func (r *round2) MessageContent() round.Content {
	return &Sign2{}
}

func (m *Sign2) Validate() error {
	if m == nil {
		return errors.New("sign.round1: message is nil")
	}
	if m.G == nil || m.K == nil {
		return errors.New("sign.round1: K or G is nil")
	}
	return nil
}

func (m *Sign2) RoundNumber() types.RoundNumber {
	return 2
}
