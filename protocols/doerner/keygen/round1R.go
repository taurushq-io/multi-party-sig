package keygen

import (
	"crypto/rand"

	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

// message1R is the message we send in this round.
type message1R struct {
	// Commit is the commitment to our public point.
	Commit hash.Commitment
	// ChainKeyCommit is the commitment to our ChainKey randomness
	ChainKeyCommit hash.Commitment
	// OtMsg is the underlying OT setup message.
	OtMsg *ot.CorreOTSetupReceiveRound1Message
}

func (message1R) RoundNumber() round.Number { return 1 }

// round1R corresponds to the first round from the Receiver's perspective.
type round1R struct {
	*round.Helper
	receiver *ot.CorreOTSetupReceiver
}

// VerifyMessage implements round.Round.
//
// Since this is the start of the protocol, we aren't expecting to have received
// any messages yet, so we do nothing.
func (r *round1R) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *round1R) StoreMessage(round.Message) error { return nil }

func (r *round1R) Finalize(out chan<- *round.Message) (round.Session, error) {
	secretShare := sample.Scalar(rand.Reader, r.Group())
	publicShare := secretShare.ActOnBase()
	commit, decommit, err := r.Hash().Commit(publicShare)
	if err != nil {
		return r, err
	}
	chainKey := make([]byte, params.SecBytes)
	_, _ = rand.Read(chainKey)
	chainKeyCommit, chainKeyDecommit, err := r.Hash().Commit(chainKey)
	if err != nil {
		return r, err
	}
	otMsg := r.receiver.Round1()
	if err := r.SendMessage(out, &message1R{commit, chainKeyCommit, otMsg}, ""); err != nil {
		return r, err
	}
	return &round2R{round1R: r, decommit: decommit, chainKeyDecommit: chainKeyDecommit, ourChainKey: chainKey, secretShare: secretShare, publicShare: publicShare}, nil
}

// MessageContent imlpements round.Round.
func (round1R) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round1R) Number() round.Number { return 1 }
