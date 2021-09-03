package keygen

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
)

type message2R struct {
	Decommit    hash.Decommitment
	PublicShare curve.Point
	Proof       *zksch.Proof
	OtMsg       *ot.CorreOTSetupReceiveRound2Message
}

func (message2R) RoundNumber() round.Number { return 2 }

type round2R struct {
	*round1R
	decommit    hash.Decommitment
	secretShare curve.Scalar
	publicShare curve.Point
	public      curve.Point
	otMsg       *ot.CorreOTSetupReceiveRound2Message
}

func (r *round2R) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message1S)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if body.Proof == nil || body.PublicShare == nil || body.OtMsg == nil {
		return round.ErrNilFields
	}
	if !body.Proof.Verify(r.Hash(), body.PublicShare, nil) {
		return errors.New("invalid Schnorr proof")
	}
	return nil
}

func (r *round2R) StoreMessage(msg round.Message) (err error) {
	body := msg.Content.(*message1S)
	r.otMsg, err = r.receiver.Round2(body.OtMsg)
	if err != nil {
		return err
	}
	r.public = r.secretShare.Act(body.PublicShare)
	return nil
}

func (r *round2R) Finalize(out chan<- *round.Message) (round.Session, error) {
	proof := zksch.NewProof(r.Hash(), r.publicShare, r.secretShare, nil)
	if err := r.SendMessage(out, &message2R{r.decommit, r.publicShare, proof, r.otMsg}, ""); err != nil {
		return r, err
	}
	return &round3R{round2R: r}, nil
}

func (r *round2R) MessageContent() round.Content {
	group := r.Group()
	return &message1S{PublicShare: group.NewPoint(), Proof: zksch.EmptyProof(group)}
}

func (round2R) Number() round.Number {
	return 2
}
