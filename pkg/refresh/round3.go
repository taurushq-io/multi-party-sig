package refresh

import (
	"bytes"
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	zkmod "github.com/taurusgroup/cmp-ecdsa/pkg/refresh/mod"
	zkprm "github.com/taurusgroup/cmp-ecdsa/pkg/refresh/prm"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

type round3 struct {
	*round2
}

func (round *round3) ProcessMessage(msg message.Message) error {
	j := msg.GetFrom()
	partyJ := round.parties[j]
	if err := partyJ.StoreMessage(msg); err != nil {
		return err
	}

	// Check Commitment
	computedV, err := partyJ.message2.Hash(round.session, j)
	if err != nil {
		panic("")
	}
	if !bytes.Equal(partyJ.CommitMessage2, computedV) {
		panic("")
	}

	if partyJ.N.BitLen() != params.PaillierBits {
		return errors.New("N is the wrong number of bits")
	}

	// Check against ID
	for _, A := range partyJ.A {
		if A.IsIdentity() {
			return errors.New("commitment A is 0")
		}
	}
	if partyJ.B.IsIdentity() {
		return errors.New("commitment B is 0")
	}
	if partyJ.Y.IsIdentity() {
		return errors.New("elGamal Y is 0")
	}

	// Verify shares sum to 0
	sum := curve.NewIdentityPoint()
	for _, X := range partyJ.X {
		sum.Add(sum, X)
	}
	if !sum.IsIdentity() {
		return errors.New("sum of public keys is not 0")
	}

	round.parties[j].PaillierPublic = paillier.NewPublicKey(partyJ.N)

	return nil
}

func (round *round3) GenerateMessages() ([]*message.Message, error) {
	// ρ = ⊕ⱼ ρⱼ
	rhoLen := 64
	rho := make([]byte, rhoLen)
	for _, partyJ := range round.parties {
		for i := 0; i < rhoLen; i++ {
			rho[i] ^= partyJ.Rho[i]
		}
	}

	// Write rho to the hash state
	if err := round.session.UpdateParams(rho); err != nil {
		return nil, err
	}

	pi := round.thisParty
	mod, err := zkmod.NewProof(round.session.HashForSelf(), zkmod.Public{N: pi.N}, zkmod.Private{
		P:   round.p,
		Q:   round.q,
		Phi: round.phi,
	})
	if err != nil {
		return nil, err
	}

	prm, err := zkprm.NewProof(round.session.HashForSelf(), zkprm.Public{
		N: pi.N,
		S: pi.S,
		T: pi.T,
	}, zkprm.Private{
		Lambda: round.lambda,
		Phi:    round.phi,
	})
	if err != nil {
		return nil, err
	}

	// Compute ZKPoK for Y = gʸ
	B := round.thisParty.B
	b := round.schRandB
	Y := round.thisParty.Y
	y := round.y
	schnorrY, err := zksch.Prove(round.session.HashForSelf(), B, Y, b, y)
	if err != nil {
		return nil, err
	}

	msgs := make([]*message3, 0, round.session.N())
	for j, partyJ := range round.parties {
		if j == round.session.SelfID() {
			continue
		}
		// Encrypt share
		C, _ := partyJ.PaillierPublic.Enc(round.sentShares[j].BigInt(), nil)

		// Compute ZKPoK for X = gˣ
		A := round.thisParty.A[j]
		a := round.schRandA[j]
		X := round.thisParty.X[j]
		x := round.sentShares[j]
		schnorrX, err := zksch.Prove(round.session.HashForSelf(), A, X, a, x)
		if err != nil {
			return nil, err
		}

		msgs = append(msgs, &message3{
			C:    C,
			Mod:  mod,
			Prm:  prm,
			SchX: schnorrX,
			SchY: schnorrY,
		})
	}

	return nil, nil
}
