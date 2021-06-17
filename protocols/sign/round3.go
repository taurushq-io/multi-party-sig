package sign

import (
	"bytes"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zklogstar "github.com/taurusgroup/cmp-ecdsa/pkg/zk/logstar"
)

type round3 struct {
	*round2
	// Gamma = ∑ᵢ Γᵢ
	Gamma *curve.Point

	// ChiShare = χᵢ
	ChiShare *curve.Scalar
}

// ProcessMessage implements round.Round
//
// - verify Hash(ssid, K₁, G₁, ..., Kₙ, Gₙ)
// - store MtA data
// - verify zkproofs affg (2x) zklog*
func (r *round3) ProcessMessage(msg round.Message) error {
	j := msg.GetHeader().From
	partyJ := r.parties[j]
	body := msg.(*Message).GetSign2()

	if !bytes.Equal(body.EchoHash, r.EchoHash) {
		return fmt.Errorf("sign.round3.ProcessMessage(): party %s: provided hash is different", j)
	}

	if !body.DeltaMtA.VerifyAffG(r.Hash.CloneWithID(j), body.BigGammaShare, r.Self.K, partyJ.Public, r.Self.Public, nil) {
		return fmt.Errorf("sign.round3.ProcessMessage(): party %s: affg proof failed to verify for Delta MtA", j)
	}
	if !body.ChiMtA.VerifyAffG(r.Hash.CloneWithID(j), partyJ.ECDSA, r.Self.K, partyJ.Public, r.Self.Public, nil) {
		return fmt.Errorf("sign.round3.ProcessMessage(): party %s: affg proof failed to verify for Chi MtA", j)
	}

	zkLogPublic := zklogstar.Public{
		C:      partyJ.G,
		X:      body.BigGammaShare,
		Prover: partyJ.Paillier,
		Aux:    r.Self.Pedersen,
	}
	if !body.ProofLog.Verify(r.Hash.CloneWithID(j), zkLogPublic) {
		return fmt.Errorf("sign.round3.ProcessMessage(): party %s: log proof failed to verify", j)
	}

	partyJ.BigGammaShare = body.BigGammaShare

	// δᵢⱼ = αᵢⱼ + βᵢⱼ
	deltaShare := curve.NewScalarBigInt(r.Secret.Paillier.Dec(body.DeltaMtA.D))
	deltaShare.Add(deltaShare, partyJ.DeltaMtA.Beta)
	partyJ.DeltaShareMtA = deltaShare
	// χᵢⱼ = α̂ᵢⱼ +  ̂βᵢⱼ
	chiShare := curve.NewScalarBigInt(r.Secret.Paillier.Dec(body.ChiMtA.D))
	chiShare.Add(chiShare, partyJ.ChiMtA.Beta)
	partyJ.ChiShareMtA = chiShare

	return partyJ.AddMessage(msg)
}

// GenerateMessages implements round.Round
//
// - Γ = ∑ⱼ Γⱼ
// - Δᵢ = [kᵢ]Γ
// - δᵢ = γᵢ kᵢ + ∑ⱼ δᵢⱼ
// - χᵢ = xᵢ kᵢ + ∑ⱼ χᵢⱼ
func (r *round3) GenerateMessages() ([]round.Message, error) {
	// Γ = ∑ⱼ Γⱼ
	r.Gamma = curve.NewIdentityPoint()
	for _, partyJ := range r.parties {
		r.Gamma.Add(r.Gamma, partyJ.BigGammaShare)
	}

	// Δᵢ = [kᵢ]Γ
	r.Self.BigDeltaShare = curve.NewIdentityPoint().ScalarMult(r.KShare, r.Gamma)

	// δᵢ = γᵢ kᵢ
	r.Self.DeltaShare = curve.NewScalar().Multiply(r.GammaShare, r.KShare)

	// χᵢ = xᵢ kᵢ
	r.ChiShare = curve.NewScalar().Multiply(r.Secret.ECDSA, r.KShare)

	for j, partyJ := range r.parties {
		if j == r.SelfID {
			continue
		}
		// δᵢ += αᵢⱼ + βᵢⱼ
		r.Self.DeltaShare.Add(r.Self.DeltaShare, partyJ.DeltaShareMtA)

		// χᵢ += α̂ᵢⱼ +  ̂βᵢⱼ
		r.ChiShare.Add(r.ChiShare, partyJ.ChiShareMtA)
	}

	zkPrivate := zklogstar.Private{
		X:   r.KShare.BigInt(),
		Rho: r.KNonce,
	}
	messages := make([]round.Message, 0, r.S.N()-1)
	for j, partyJ := range r.parties {
		if j == r.SelfID {
			continue
		}

		proofLog := zklogstar.NewProof(r.Hash.CloneWithID(r.SelfID), zklogstar.Public{
			C:      r.Self.K,
			X:      r.Self.BigDeltaShare,
			G:      r.Gamma,
			Prover: r.Self.Paillier,
			Aux:    partyJ.Pedersen,
		}, zkPrivate)

		sign3 := &Sign3{
			DeltaShare:    r.Self.DeltaShare,
			BigDeltaShare: r.Self.BigDeltaShare,
			ProofLog:      proofLog,
		}

		messages = append(messages, NewMessageSign3(r.SelfID, j, sign3))
	}

	return messages, nil
}

// Finalize implements round.Round
func (r *round3) Finalize() (round.Round, error) {
	return &round4{
		round3: r,
	}, nil
}

func (r *round3) MessageType() round.MessageType {
	return MessageTypeSign2
}
