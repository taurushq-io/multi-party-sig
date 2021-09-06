package keygen

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
)

// message2S is the message sent by the Sender at the end of the second round.
type message2S struct {
	OtMsg *ot.CorreOTSetupSendRound2Message
}

func (message2S) RoundNumber() round.Number { return 3 }

// round2S is the second round from the Sender's perspective.
type round2S struct {
	*round1S
	// secretShare is our share of the secret key.
	secretShare curve.Scalar
	// publicShare is secretShare times the generator of the group.
	publicShare curve.Point
	// public is the shared public key.
	public curve.Point
	otMsg  *ot.CorreOTSetupSendRound2Message
}

func (r *round2S) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message2R)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if body.PublicShare == nil || body.Proof == nil || body.OtMsg == nil {
		return round.ErrNilFields
	}
	if err := body.Decommit.Validate(); err != nil {
		return err
	}
	if !r.Hash().Decommit(r.receiverCommit, body.Decommit, body.PublicShare) {
		return errors.New("invalid commitment")
	}
	if !body.Proof.Verify(r.Hash(), body.PublicShare, nil) {
		return errors.New("invalid Schnorr proof")
	}
	return nil
}

func (r *round2S) StoreMessage(msg round.Message) error {
	body := msg.Content.(*message2R)
	r.public = r.publicShare.Add(body.PublicShare)
	r.otMsg = r.sender.Round2(body.OtMsg)
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
	return &message2R{PublicShare: group.NewPoint(), Proof: zksch.EmptyProof(group)}
}

func (round2S) Number() round.Number {
	return 2
}
