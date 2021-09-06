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

// message1S is the message the Sender provides in response to the first round.
type message1S struct {
	// PublicShare is our secret share times the group generator.
	PublicShare curve.Point
	// Proof is the proof of knowledge for the discrete logarithm of PublicShare.
	Proof *zksch.Proof
	// OtMsg is the forwarded message for the underlying OT setup.
	OtMsg *ot.CorreOTSetupSendRound1Message
}

func (message1S) RoundNumber() round.Number { return 2 }

// round1S corresponds to the second round from the Sender's perspective.
type round1S struct {
	*round.Helper
	sender *ot.CorreOTSetupSender
	// The commitment sent to us by the receiver.
	receiverCommit hash.Commitment
	otMsg          *ot.CorreOTSetupSendRound1Message
}

func (r *round1S) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message1R)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if err := body.Commit.Validate(); err != nil {
		return err
	}

	if body.OtMsg == nil {
		return round.ErrNilFields
	}

	return nil
}

func (r *round1S) StoreMessage(msg round.Message) (err error) {
	body := msg.Content.(*message1R)
	r.otMsg, err = r.sender.Round1(body.OtMsg)
	if err != nil {
		return err
	}
	r.receiverCommit = body.Commit
	return nil
}

func (r *round1S) Finalize(out chan<- *round.Message) (round.Session, error) {
	secretShare := sample.Scalar(rand.Reader, r.Group())
	publicShare := secretShare.ActOnBase()
	proof := zksch.NewProof(r.Hash(), publicShare, secretShare, nil)
	if err := r.SendMessage(out, &message1S{publicShare, proof, r.otMsg}, ""); err != nil {
		return r, err
	}
	return &round2S{round1S: r, secretShare: secretShare, publicShare: publicShare}, nil
}

func (r *round1S) MessageContent() round.Content {
	return &message1R{OtMsg: ot.EmptyCorreOTSetupReceiveRound1Message(r.Group())}
}

func (round1S) Number() round.Number { return 1 }
