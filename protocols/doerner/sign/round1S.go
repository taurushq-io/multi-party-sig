package sign

import (
	"crypto/rand"
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
	"github.com/taurusgroup/multi-party-sig/protocols/doerner/keygen"
)

type message1S struct {
	RPrime  curve.Point
	RProof  *zksch.Proof
	MulMsg0 *ot.MultiplySendRound1Message
	MulMsg1 *ot.MultiplySendRound1Message
	MulMsg2 *ot.MultiplySendRound1Message
	MuPhi   curve.Scalar
	MuSig   curve.Scalar
}

func (message1S) RoundNumber() round.Number { return 2 }

// round1S is the first round from the Sender's perspective.
type round1S struct {
	*round.Helper
	config *keygen.ConfigSender
	// The message hash to be signed.
	hash []byte
	// The nonce commitment produced by the Receiver.
	D curve.Point
	// The three multiplication messages we've received.
	mulMsg0 *ot.MultiplyReceiveRound1Message
	mulMsg1 *ot.MultiplyReceiveRound1Message
	mulMsg2 *ot.MultiplyReceiveRound1Message
}

func (r *round1S) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message1R)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if body.D == nil || body.MulMsg0 == nil || body.MulMsg1 == nil || body.MulMsg2 == nil {
		return round.ErrNilFields
	}
	if body.D.IsIdentity() {
		return errors.New("invalid D point")
	}
	return nil
}

func (r *round1S) StoreMessage(msg round.Message) error {
	body := msg.Content.(*message1R)
	r.D = body.D
	r.mulMsg0 = body.MulMsg0
	r.mulMsg1 = body.MulMsg1
	r.mulMsg2 = body.MulMsg2
	return nil
}

func (r *round1S) Finalize(out chan<- *round.Message) (round.Session, error) {
	group := r.Group()

	kAPrime := sample.Scalar(rand.Reader, group)
	RPrime := kAPrime.Act(r.D)

	H := r.Hash()
	_ = H.WriteAny(RPrime)
	kA := sample.Scalar(H.Digest(), group).Add(kAPrime)

	R := kA.Act(r.D)
	RProof := zksch.NewProof(r.Hash(), R, kA, r.D)

	phi := sample.Scalar(rand.Reader, group)
	kAInv := group.NewScalar().Set(kA).Invert()
	alpha1 := group.NewScalar().Set(r.config.SecretShare).Mul(kAInv)
	alpha2 := group.NewScalar().Set(kAInv)
	alpha0 := kAInv
	alpha0.Add(phi)

	tag0 := &hash.BytesWithDomain{TheDomain: "Multiply0", Bytes: nil}
	multiply0 := ot.NewMultiplySender(r.Hash().Fork(tag0), r.config.Setup, alpha0)
	tag1 := &hash.BytesWithDomain{TheDomain: "Multiply1", Bytes: nil}
	multiply1 := ot.NewMultiplySender(r.Hash().Fork(tag1), r.config.Setup, alpha1)
	tag2 := &hash.BytesWithDomain{TheDomain: "Multiply1", Bytes: nil}
	multiply2 := ot.NewMultiplySender(r.Hash().Fork(tag2), r.config.Setup, alpha2)

	msg0, tA1, err := multiply0.Round1(r.mulMsg0)
	if err != nil {
		return r, err
	}
	msg1, tA21, err := multiply1.Round1(r.mulMsg1)
	if err != nil {
		return r, err
	}
	msg2, tA22, err := multiply2.Round1(r.mulMsg2)
	if err != nil {
		return r, err
	}
	tA2 := tA21.Add(tA22)

	m := curve.FromHash(group, r.hash)

	Gamma1 := group.NewBasePoint().Add(phi.Act(kA.ActOnBase())).Sub(tA1.Act(R))

	H = r.Hash()
	_ = H.WriteAny(Gamma1)
	HGamma1 := sample.Scalar(H.Digest(), group)

	muPhi := HGamma1.Add(phi)

	sigA := group.NewScalar().Set(m).Mul(tA1).Add(R.XScalar().Mul(tA2))
	Gamma2 := tA1.Act(r.config.Public).Sub(tA2.ActOnBase())

	H = r.Hash()
	_ = H.WriteAny(Gamma2)
	HGamma2 := sample.Scalar(H.Digest(), group)

	muSig := HGamma2.Add(sigA)

	if err := r.SendMessage(out, &message1S{RPrime, RProof, msg0, msg1, msg2, muPhi, muSig}, ""); err != nil {
		return r, err
	}

	return &round2S{round1S: r}, nil
}

func (r *round1S) MessageContent() round.Content {
	group := r.Group()
	return &message1R{D: group.NewPoint()}
}

func (round1S) Number() round.Number { return 1 }
