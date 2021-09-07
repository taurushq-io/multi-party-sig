package sign

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
)

// message2R is the last message sent by the Receiver.
type message2R struct {
	// Sig is the final signature produced by the protocol.
	Sig ecdsa.Signature
}

func (message2R) RoundNumber() round.Number {
	return 2
}

type round2R struct {
	*round1R
	// kBInv is the inverse of our nonce.
	kBInv curve.Scalar
	// D is the commitment to our nonce.
	D curve.Point
	// We have three multiplication instances.
	multiply0 *ot.MultiplyReceiver
	multiply1 *ot.MultiplyReceiver
	multiply2 *ot.MultiplyReceiver
	// RPrime is the point sent by the Sender.
	RPrime curve.Point
	// RProof is a proof related to the derived point R.
	RProof  *zksch.Proof
	MulMsg0 *ot.MultiplySendRound1Message
	MulMsg1 *ot.MultiplySendRound1Message
	MulMsg2 *ot.MultiplySendRound1Message
	// Encrypted versions of phi and sig.
	MuPhi curve.Scalar
	MuSig curve.Scalar
}

func (r *round2R) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message1S)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.RPrime == nil || body.RProof == nil || body.MulMsg0 == nil || body.MulMsg1 == nil || body.MulMsg2 == nil || body.MuPhi == nil || body.MuSig == nil {
		return round.ErrNilFields
	}

	return nil
}

func (r *round2R) StoreMessage(msg round.Message) (err error) {
	body := msg.Content.(*message1S)
	r.RPrime = body.RPrime
	r.RProof = body.RProof
	r.MulMsg0 = body.MulMsg0
	r.MulMsg1 = body.MulMsg1
	r.MulMsg2 = body.MulMsg2
	r.MuPhi = body.MuPhi
	r.MuSig = body.MuSig
	return nil
}

func (r *round2R) Finalize(out chan<- *round.Message) (round.Session, error) {
	group := r.Group()

	hash := r.Hash()
	_ = hash.WriteAny(r.RPrime)
	R := sample.Scalar(hash.Digest(), group).Act(r.D).Add(r.RPrime)
	if !r.RProof.Verify(r.Hash(), R, r.D) {
		return nil, errors.New("failed to verify schnorr proof")
	}

	tB1, err := r.multiply0.Round2(r.MulMsg0)
	if err != nil {
		return r, err
	}
	tB21, err := r.multiply1.Round2(r.MulMsg1)
	if err != nil {
		return r, err
	}
	tB22, err := r.multiply2.Round2(r.MulMsg2)
	if err != nil {
		return r, err
	}
	tB2 := tB21.Add(tB22)

	m := curve.FromHash(group, r.hash)

	Gamma1 := tB1.Act(R)

	hash = r.Hash()
	_ = hash.WriteAny(Gamma1)
	HGamma1 := sample.Scalar(hash.Digest(), group)

	phi := HGamma1.Negate().Add(r.MuPhi)
	theta := group.NewScalar().Set(phi).Mul(r.kBInv).Negate().Add(tB1)

	sigB := group.NewScalar().Set(m).Mul(theta).Add(R.XScalar().Mul(tB2))

	Gamma2 := tB2.ActOnBase().Sub(theta.Act(r.config.Public))

	hash = r.Hash()
	_ = hash.WriteAny(Gamma2)
	HGamma2 := sample.Scalar(hash.Digest(), group)

	sigAB := sigB.Add(r.MuSig).Sub(HGamma2)

	sig := ecdsa.Signature{R: R, S: sigAB}
	if !sig.Verify(r.config.Public, r.hash) {
		return nil, errors.New("failed to verify signature")
	}
	if err := r.SendMessage(out, &message2R{sig}, ""); err != nil {
		return r, err
	}
	return r.ResultRound(&sig), nil
}

func (r *round2R) MessageContent() round.Content {
	group := r.Group()
	return &message1S{
		RPrime:  group.NewPoint(),
		RProof:  zksch.EmptyProof(group),
		MulMsg0: r.multiply0.EmptyMultiplySendRound1Message(),
		MulMsg1: r.multiply1.EmptyMultiplySendRound1Message(),
		MulMsg2: r.multiply2.EmptyMultiplySendRound1Message(),
		MuPhi:   group.NewScalar(),
		MuSig:   group.NewScalar(),
	}
}

func (round2R) Number() round.Number { return 2 }
