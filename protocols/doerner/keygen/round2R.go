package keygen

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
)

// message2R is the message sent by the Receiver at the start of the second round.
type message2R struct {
	// Decommit reveals the value that we committed to earlier.
	Decommit hash.Decommitment
	// ChainKeyDecommit is the decommitment to our chain key
	ChainKeyDecommit hash.Decommitment
	// RefreshDecommit is the decommitment to our refresh value
	RefreshDecommit hash.Decommitment
	// ChainKey is our contribution to the chain key.
	ChainKey []byte
	// PublicShare is our secret share times the group generator.
	PublicShare curve.Point
	// RefreshScalar is our refresh to the secret shares.
	RefreshScalar curve.Scalar
	// Proof is a proof of knowledge of the discrete logarithm of PublicShare.
	Proof *zksch.Proof
	OtMsg *ot.CorreOTSetupReceiveRound2Message
}

func (message2R) RoundNumber() round.Number { return 2 }

type round2R struct {
	*round1R
	// proof is a proof of knowledge for the discrete logarithm of our public share.
	proof *zksch.Proof
	// decommit is the decommitment to our first commitment
	decommit hash.Decommitment
	// chainKeyDecommit is the decommitment to our chain key commitment
	chainKeyDecommit hash.Decommitment
	// refreshDecommit is the decommitment to our refresh commitment
	refreshDecommit hash.Decommitment
	// refreshScalar is our contribution to refreshing the shares
	refreshScalar curve.Scalar
	// ourChainKey is our contribution to the chain key
	ourChainKey []byte
	// chainKey is our collective chain key
	chainKey []byte
	otMsg    *ot.CorreOTSetupReceiveRound2Message
}

func (r *round2R) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message1S)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if body.Proof == nil || body.PublicShare == nil || body.RefreshScalar == nil || body.OtMsg == nil {
		return round.ErrNilFields
	}
	if !body.Proof.Verify(r.Hash(), body.PublicShare, nil) {
		return errors.New("invalid Schnorr proof")
	}
	if len(body.ChainKey) != params.SecBytes {
		return errors.New("chain key too short")
	}
	return nil
}

func (r *round2R) StoreMessage(msg round.Message) (err error) {
	body := msg.Content.(*message1S)
	r.otMsg, err = r.receiver.Round2(body.OtMsg)
	if err != nil {
		return err
	}
	if !r.refresh {
		r.public = r.publicShare.Add(body.PublicShare)
	}
	r.chainKey = body.ChainKey
	for i := 0; i < len(r.chainKey) && i < len(r.ourChainKey); i++ {
		r.chainKey[i] ^= r.ourChainKey[i]
	}
	r.secretShare = r.Group().NewScalar().Set(r.secretShare).Add(r.refreshScalar).Sub(body.RefreshScalar)
	return nil
}

func (r *round2R) Finalize(out chan<- *round.Message) (round.Session, error) {
	if err := r.SendMessage(out, &message2R{r.decommit, r.chainKeyDecommit, r.refreshDecommit, r.ourChainKey, r.publicShare, r.refreshScalar, r.proof, r.otMsg}, ""); err != nil {
		return r, err
	}
	return &round3R{round2R: r}, nil
}

func (r *round2R) MessageContent() round.Content {
	group := r.Group()
	return &message1S{
		PublicShare:   group.NewPoint(),
		RefreshScalar: group.NewScalar(),
		Proof:         zksch.EmptyProof(group),
	}
}

func (round2R) Number() round.Number {
	return 2
}
