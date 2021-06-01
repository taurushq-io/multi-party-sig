package sign

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	signature2 "github.com/taurusgroup/cmp-ecdsa/protocols/sign/signature"
)

type output struct {
	*round4
	// sigma = σ = km + rχ
	// this is the full "s" part of the signature
	sigma *curve.Scalar

	// signature wraps (R,S)
	signature *signature2.Signature
}

// ProcessMessage implements round.Round
//
//
func (round *output) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFromID()
	partyJ := round.parties[j]

	body := msg.GetSign4()

	sigma, err := body.GetSigma().Unmarshal()
	if err != nil {
		return fmt.Errorf("sign.output.ProcessMessage(): party %s: unmarshal sigma: %w", j, err)
	}
	if sigma.IsZero() {
		return fmt.Errorf("sign.output.ProcessMessage(): party %s: sigma is 0", j)
	}
	partyJ.sigma = sigma

	return nil
}

// GenerateMessages implements round.Round
//
//
func (round *output) GenerateMessages() ([]*pb.Message, error) {
	// compute σ = ∑ⱼ σⱼ
	round.sigma = curve.NewScalar()
	for _, partyJ := range round.parties {
		round.sigma.Add(round.sigma, partyJ.sigma)
	}

	round.signature = &signature2.Signature{
		R: round.R,
		S: round.sigma,
	}

	// Verify signature using Go's ECDSA lib
	if !ecdsa.Verify(round.S.PublicKey, round.S.Message, round.r.BigInt(), round.sigma.BigInt()) {
		return nil, errors.New("sign.output.GenerateMessages(): failed to validate signature with Go stdlib")
	}
	pk := curve.NewIdentityPoint().SetPublicKey(round.S.PublicKey)
	if !round.signature.Verify(pk, round.S.Message) {
		round.abort = true
		return round.GenerateMessagesAbort()
	}
	return nil, nil
}

// Finalize implements round.Round
//
//
func (round *output) Finalize() (round.Round, error) {
	if round.abort {
		return &abort2{round}, nil
	}
	return nil, nil
}

func (round *output) GenerateMessagesAbort() ([]*pb.Message, error) {
	return nil, nil
}

func (round *output) MessageType() pb.MessageType {
	return pb.MessageType_TypeSign4
}
