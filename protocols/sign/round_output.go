package sign

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	signature2 "github.com/taurusgroup/cmp-ecdsa/protocols/sign/signature"
)

type output struct {
	*round4
	sigma *curve.Scalar // sigma = σ = km + rχ

	signature *signature2.Signature
}

func (round *output) ProcessMessage(msg *pb.Message) error {
	j := msg.GetFromID()
	partyJ := round.parties[j]

	body := msg.GetSign4()

	partyJ.sigma = body.GetSigma().Unmarshal()

	return nil
}

func (round *output) GenerateMessages() ([]*pb.Message, error) {
	round.sigma = curve.NewScalar()
	for _, partyJ := range round.parties {
		round.sigma.Add(round.sigma, partyJ.sigma)
	}

	round.signature = &signature2.Signature{
		R: round.R,
		S: round.sigma,
	}

	ecdsaPk, err := round.S.PublicKey()
	if err != nil {
		return nil, err
	}
	if !ecdsa.Verify(ecdsaPk, round.message, round.r.BigInt(), round.sigma.BigInt()) {
		fmt.Println("fail")
	}
	pk := curve.NewIdentityPoint().SetPublicKey(ecdsaPk)
	if !round.signature.Verify(pk, round.message) {
		round.abort = true
		return round.GenerateMessagesAbort()
	}
	return nil, nil
}

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
