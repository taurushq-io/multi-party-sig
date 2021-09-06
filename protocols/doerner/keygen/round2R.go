package keygen

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
)

// message2R is the message sent by the Receiver at the start of the second round.
type message2R struct {
	// Decommit reveals the value that we committed to earlier.
	Decommit hash.Decommitment
	// PublicShare is our secret share times the group generator.
	PublicShare curve.Point
	// Proof is a proof of knowledge of the discrete logarithm of PublicShare.
	Proof *zksch.Proof
	OtMsg *ot.CorreOTSetupReceiveRound2Message
}

func (message2R) RoundNumber() round.Number { return 2 }

type round2R struct {
	*round1R
	// decommit is the decommitment to our first commitment
	decommit hash.Decommitment
	// secretShare is our additive share of the secret key
	secretShare curve.Scalar
	// publicShare is secretShare * G
	publicShare curve.Point
	// public is the shared public key.
	public curve.Point
	otMsg  *ot.CorreOTSetupReceiveRound2Message
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
	r.public = r.publicShare.Add(body.PublicShare)
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
