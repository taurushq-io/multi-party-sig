package sign

import (
	"crypto/rand"

	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/protocols/doerner/keygen"
)

type message1R struct {
	D       curve.Point
	MulMsg0 *ot.MultiplyReceiveRound1Message
	MulMsg1 *ot.MultiplyReceiveRound1Message
}

func (message1R) RoundNumber() round.Number { return 1 }

type round1R struct {
	*round.Helper
	hash   []byte
	config *keygen.ConfigReceiver
}

func (r *round1R) VerifyMessage(round.Message) error { return nil }

func (r *round1R) StoreMessage(round.Message) error { return nil }

func (r *round1R) Finalize(out chan<- *round.Message) (round.Session, error) {
	kB := sample.Scalar(rand.Reader, r.Group())
	D := kB.ActOnBase()
	kB.Invert()
	multiply0, err := ot.NewMultiplyReceiver(r.Hash(), r.config.Setup, kB)
	if err != nil {
		return r, err
	}
	beta := r.Group().NewScalar().Set(r.config.SecretShare).Mul(kB)
	multiply1, err := ot.NewMultiplyReceiver(r.Hash(), r.config.Setup, beta)
	if err != nil {
		return r, err
	}
	msg0 := multiply0.Round1()
	msg1 := multiply1.Round1()
	if err := r.SendMessage(out, &message1R{D, msg0, msg1}, ""); err != nil {
		return r, err
	}
	return &round2R{round1R: r, kBInv: kB, D: D, multiply0: multiply0, multiply1: multiply1}, nil
}

func (round1R) MessageContent() round.Content { return nil }

func (round1R) Number() round.Number { return 1 }
