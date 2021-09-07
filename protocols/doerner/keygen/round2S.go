package keygen

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/params"
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
	// chainKey is our share of the chain key
	chainKey []byte
	// refreshScalar is our contribution to refreshing the shares.
	refreshScalar curve.Scalar
	otMsg         *ot.CorreOTSetupSendRound2Message
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
	if len(body.ChainKey) != params.SecBytes {
		return errors.New("chain key too short")
	}
	if !r.Hash().Decommit(r.chainKeyCommit, body.ChainKeyDecommit, body.ChainKey) {
		return errors.New("invalid commitment")
	}
	if !r.Hash().Decommit(r.refreshCommit, body.RefreshDecommit, body.RefreshScalar) {
		return errors.New("invalid commitment")
	}
	if !body.Proof.Verify(r.Hash(), body.PublicShare, nil) {
		return errors.New("invalid Schnorr proof")
	}
	return nil
}

func (r *round2S) StoreMessage(msg round.Message) error {
	body := msg.Content.(*message2R)
	if !r.refresh {
		r.public = r.publicShare.Add(body.PublicShare)
	}
	r.otMsg = r.sender.Round2(body.OtMsg)
	for i := 0; i < len(r.chainKey) && i < len(body.ChainKey); i++ {
		r.chainKey[i] ^= body.ChainKey[i]
	}
	r.secretShare = r.Group().NewScalar().Set(r.secretShare).Add(r.refreshScalar).Sub(body.RefreshScalar)
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
	return &message2R{
		PublicShare:   group.NewPoint(),
		RefreshScalar: group.NewScalar(),
		Proof:         zksch.EmptyProof(group),
	}
}

func (round2S) Number() round.Number {
	return 2
}
