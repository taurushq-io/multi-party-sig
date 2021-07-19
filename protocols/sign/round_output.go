package sign

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
	"github.com/taurusgroup/cmp-ecdsa/protocols/sign/signature"
)

type output struct {
	*round4
	// Signature wraps (R,S)
	Signature *signature.Signature
}

// ProcessMessage implements round.Round
//
// - σⱼ != 0
func (r *output) ProcessMessage(msg round.Message) error {
	j := msg.GetHeader().From
	partyJ := r.parties[j]
	body := msg.(*Message).GetSign4()

	if body.SigmaShare.IsZero() {
		return fmt.Errorf("sign.output.ProcessMessage(): party %s: sigma is 0", j)
	}
	partyJ.SigmaShare = body.SigmaShare

	return nil
}

// GenerateMessages implements round.Round
//
// - compute σ = ∑ⱼ σⱼ
// - verify signature
func (r *output) GenerateMessages() ([]round.Message, error) {
	// compute σ = ∑ⱼ σⱼ
	S := curve.NewScalar()
	for _, partyJ := range r.parties {
		S.Add(S, partyJ.SigmaShare)
	}

	r.Signature = &signature.Signature{
		R: r.BigR,
		S: S,
	}

	// Verify signature using Go's ECDSA lib
	if !ecdsa.Verify(r.S.PublicKey(), r.Message, r.r.BigInt(), r.Signature.S.BigInt()) {
		return nil, errors.New("sign.output.GenerateMessages(): failed to validate signature with Go stdlib")
	}
	pk := curve.FromPublicKey(r.S.PublicKey())
	if !r.Signature.Verify(pk, r.Message) {
		return nil, errors.New("sign.output.GenerateMessages(): failed to validate signature with Go stdlib")
	}
	return nil, nil
}

	return nil
}

// Next implements round.Round
func (r *output) Next() round.Round {
	return nil
}

func (r *output) Result() interface{} {
	// This could be used to handle pre-signatures
	if r.Signature != nil {
		return &Result{Signature: r.Signature}
	}
	return nil
}

func (r *output) MessageContent() round.Content {
	return &SignOutput{}
}

func (m *SignOutput) Validate() error {
	if m == nil {
		return errors.New("sign.round4: message is nil")
	}
	if m.SigmaShare == nil {
		return errors.New("sign.round4: message contains nil fields")
	}
	return nil
}

func (m *SignOutput) RoundNumber() types.RoundNumber {
	return 5
}
