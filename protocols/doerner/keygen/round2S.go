package keygen

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
)

type message2S struct {
	otMsg *ot.CorreOTSetupSendRound2Message
}

type round2S struct {
	*round1S
	secretShare curve.Scalar
	public      curve.Point
	otMsg       *ot.CorreOTSetupSendRound2Message
}

func (r *round2S) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message2R)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if body.publicShare == nil || body.proof == nil || body.otMsg == nil {
		return round.ErrNilFields
	}
	if err := body.decommit.Validate(); err != nil {
		return err
	}
	if !r.Hash().Decommit(r.receiverCommit, body.decommit, body.publicShare) {
		return errors.New("invalid commitment")
	}
	if !body.proof.Verify(r.Hash(), body.publicShare) {
		return errors.New("invalid Schnorr proof")
	}
	return nil
}

func (r *round2S) StoreMessage(msg round.Message) error {
	body := msg.Content.(*message2R)
	r.public = r.secretShare.Act(body.publicShare)
	r.otMsg = r.sender.Round2(body.otMsg)
	return nil
}

func (r *round2S) Finalize(out chan<- *round.Message) (round.Session, error) {
	if err := r.SendMessage(out, &message2S{r.otMsg}, ""); err != nil {
		return r, err
	}
	return &round3S{round2S: r}, nil
}

func (r *round2S) MessageContent() round.Content {
	group := r.Group()
	return &message2R{publicShare: group.NewPoint(), proof: zksch.EmptyProof(group)}
}

func (round2S) Number() round.Number {
	return 2
}
