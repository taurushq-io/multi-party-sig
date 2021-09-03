package sign

import (
	"crypto/rand"
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/round"
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
	MuPhi   curve.Scalar
	MuSig   curve.Scalar
}

func (message1S) RoundNumber() round.Number { return 2 }

type round1S struct {
	*round.Helper
	config  *keygen.ConfigSender
	hash    []byte
	D       curve.Point
	mulMsg0 *ot.MultiplyReceiveRound1Message
	mulMsg1 *ot.MultiplyReceiveRound1Message
}

func (r *round1S) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message1R)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if body.D == nil || body.MulMsg0 == nil || body.MulMsg1 == nil {
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
	return nil
}

func (r *round1S) Finalize(out chan<- *round.Message) (round.Session, error) {
	group := r.Group()

	kAPrime := sample.Scalar(rand.Reader, group)
	RPrime := kAPrime.Act(r.D)

	hash := r.Hash()
	_ = hash.WriteAny(RPrime)
	kA := sample.Scalar(hash.Digest(), group).Add(kAPrime)

	R := kA.Act(r.D)
	RProof := zksch.NewProof(r.Hash(), R, kA, r.D)

	phi := sample.Scalar(rand.Reader, group)
	kAInv := group.NewScalar().Set(kA).Invert()
	alpha1 := group.NewScalar().Set(r.config.SecretShare).Mul(kAInv)
	alpha0 := kAInv
	alpha0.Add(phi)

	multiply0 := ot.NewMultiplySender(r.Hash(), r.config.Setup, alpha0)
	multiply1 := ot.NewMultiplySender(r.Hash(), r.config.Setup, alpha1)

	msg0, tA0, err := multiply0.Round1(r.mulMsg0)
	if err != nil {
		return r, err
	}
	msg1, tA1, err := multiply1.Round1(r.mulMsg1)
	if err != nil {
		return r, err
	}

	m := curve.FromHash(group, r.hash)

	Gamma1 := group.NewBasePoint().Add(phi.Act(kA.ActOnBase())).Sub(tA0.Act(R))

	hash = r.Hash()
	_ = hash.WriteAny(Gamma1)
	HGamma1 := sample.Scalar(hash.Digest(), group)

	muPhi := HGamma1.Add(phi)

	sigA := group.NewScalar().Set(m).Mul(tA0).Add(R.XScalar().Mul(tA1))
	Gamma2 := tA0.Act(r.config.Public).Sub(tA1.ActOnBase())

	hash = r.Hash()
	_ = hash.WriteAny(Gamma2)
	HGamma2 := sample.Scalar(hash.Digest(), group)

	muSig := HGamma2.Add(sigA)

	if err := r.SendMessage(out, &message1S{RPrime, RProof, msg0, msg1, muPhi, muSig}, ""); err != nil {
		return r, err
	}

	return &round2S{round1S: r}, nil
}

func (r *round1S) MessageContent() round.Content {
	group := r.Group()
	return &message1R{D: group.NewPoint()}
}

func (round1S) Number() round.Number { return 1 }
