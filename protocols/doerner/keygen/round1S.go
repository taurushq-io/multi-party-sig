package keygen

import (
	"crypto/rand"

	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
)

type message1S struct {
	publicShare curve.Point
	proof       *zksch.Proof
	otMsg       *ot.CorreOTSetupSendRound1Message
}

type round1S struct {
	*round.Helper
	sender         *ot.CorreOTSetupSender
	receiverCommit hash.Commitment
	otMsg          *ot.CorreOTSetupSendRound1Message
}

func (r *round1S) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message1R)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if err := body.commit.Validate(); err != nil {
		return err
	}

	if body.otMsg == nil {
		return round.ErrNilFields
	}

	return nil
}

func (r *round1S) StoreMessage(msg round.Message) (err error) {
	body := msg.Content.(*message1R)
	r.otMsg, err = r.sender.Round1(body.otMsg)
	if err != nil {
		return err
	}
	r.receiverCommit = body.commit
	return nil
}

func (r *round1S) Finalize(out chan<- *round.Message) (round.Session, error) {
	secretShare := sample.Scalar(rand.Reader, r.Group())
	publicShare := secretShare.ActOnBase()
	proof := zksch.NewProof(r.Hash(), publicShare, secretShare)
	if err := r.SendMessage(out, &message1S{publicShare, proof, r.otMsg}, ""); err != nil {
		return r, err
	}
	return &round2S{round1S: r, secretShare: secretShare}, nil
}

func (round1S) MessageContent() round.Content {
	return &message1R{}
}

func (round1S) Number() round.Number { return 1 }
