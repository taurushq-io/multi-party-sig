package keygen

import (
	"crypto/rand"

	"github.com/taurusgroup/multi-party-sig/internal/ot"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
)

// message1R is the message we send in this round.
type message1R struct {
	// Commit is the commitment to our public point.
	Commit hash.Commitment
	// ChainKeyCommit is the commitment to our ChainKey randomness
	ChainKeyCommit hash.Commitment
	// RefreshCommit is the commitment to our refresh scalar.
	RefreshCommit hash.Commitment
	// OtMsg is the underlying OT setup message.
	OtMsg *ot.CorreOTSetupReceiveRound1Message
}

func (message1R) RoundNumber() round.Number { return 1 }

// round1R corresponds to the first round from the Receiver's perspective.
type round1R struct {
	*round.Helper
	// refresh indicates whether or not we should refresh
	refresh bool
	// public is an existing public key, if we're refresing
	public curve.Point
	// Our generated secret share
	secretShare curve.Scalar
	// Our secret share * G
	publicShare curve.Point
	receiver    *ot.CorreOTSetupReceiver
}

// VerifyMessage implements round.Round.
//
// Since this is the start of the protocol, we aren't expecting to have received
// any messages yet, so we do nothing.
func (r *round1R) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *round1R) StoreMessage(round.Message) error { return nil }

func (r *round1R) Finalize(out chan<- *round.Message) (round.Session, error) {
	proof := zksch.NewProof(r.Hash(), r.publicShare, r.secretShare, nil)
	commit, decommit, err := r.Hash().Commit(r.publicShare)
	if err != nil {
		return r, err
	}
	chainKey := make([]byte, params.SecBytes)
	_, _ = rand.Read(chainKey)
	chainKeyCommit, chainKeyDecommit, err := r.Hash().Commit(chainKey)
	if err != nil {
		return r, err
	}
	refreshScalar := sample.Scalar(rand.Reader, r.Group())
	refreshCommit, refreshDecommit, err := r.Hash().Commit(refreshScalar)
	if err != nil {
		return r, err
	}
	otMsg := r.receiver.Round1()
	if err := r.SendMessage(out, &message1R{commit, chainKeyCommit, refreshCommit, otMsg}, ""); err != nil {
		return r, err
	}

	return &round2R{
		round1R:          r,
		proof:            proof,
		decommit:         decommit,
		chainKeyDecommit: chainKeyDecommit,
		refreshDecommit:  refreshDecommit,
		refreshScalar:    refreshScalar,
		ourChainKey:      chainKey,
	}, nil
}

// MessageContent imlpements round.Round.
func (round1R) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round1R) Number() round.Number { return 1 }
