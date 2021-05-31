package keygen_threshold

import (
	"crypto/rand"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
)

type round1 struct {
	*round.BaseRound

	thisParty *localParty
	parties   map[party.ID]*localParty

	// decommitment of the 2nd message
	decommitment hash.Decommitment // uᵢ

	// lambda is λᵢ used to generate the Pedersen parameters
	lambda *big.Int

	// poly is fᵢ(X)
	poly *polynomial.Polynomial

	// p, q primes for paillier, phi = (p-1)(q-1)
	p, q, phi *big.Int

	schnorrRand []*curve.Scalar
}

var _ round.Round = (*round1)(nil)

func (round *round1) ProcessMessage(*pb.Message) error {
	// In the first round, no messages are expected.
	return nil
}

func (round *round1) GenerateMessages() ([]*pb.Message, error) {
	var err error

	// generate Schnorr randomness and commitments
	round.thisParty.A = make([]*curve.Point, round.S.Threshold)
	round.schnorrRand = make([]*curve.Scalar, round.S.Threshold)
	for i := range round.thisParty.A {
		round.schnorrRand[i] = curve.NewScalarRandom()
		round.thisParty.A[i] = curve.NewIdentityPoint().ScalarBaseMult(round.schnorrRand[i])
	}

	// generate Paillier
	var n *big.Int
	round.p, round.q, n, round.phi = sample.Paillier()
	round.thisParty.Paillier = paillier.NewPublicKey(n)
	round.S.Secret.Paillier = paillier.NewSecretKeyFromPrimes(round.phi, round.thisParty.Paillier)

	// generate Pedersen
	s, t, lambda := sample.Pedersen(n, round.phi)
	round.thisParty.Pedersen = &pedersen.Parameters{
		N: n,
		S: s,
		T: t,
	}
	round.lambda = lambda

	// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = 0
	round.poly = polynomial.NewPolynomial(round.S.Threshold, curve.NewScalar())
	selfScalar := curve.NewScalar().SetBytes([]byte(round.SelfID))
	round.thisParty.shareReceived = round.poly.Evaluate(selfScalar)

	// set Fᵢ(X) = fᵢ(X)•G
	round.thisParty.polyExp = polynomial.NewPolynomialExponent(round.poly)

	// Sample ρ
	round.thisParty.rho = make([]byte, params.SecBytes)
	_, err = rand.Read(round.thisParty.rho)

	// commit to data in message 2
	round.thisParty.commitment, round.decommitment, err = round.H.Commit(round.SelfID,
		round.thisParty.rho, round.thisParty.polyExp, round.thisParty.A, round.thisParty.Pedersen)
	if err != nil {
		return nil, err
	}

	return []*pb.Message{{
		Type:      pb.MessageType_TypeRefresh1,
		From:      round.SelfID,
		Broadcast: pb.Broadcast_Reliable,
		RefreshT1: &pb.RefreshT1{
			Hash: round.thisParty.commitment,
		},
	}}, nil
}

func (round *round1) Finalize() (round.Round, error) {
	return &round2{round, nil}, nil
}

func (round *round1) MessageType() pb.MessageType {
	return pb.MessageType_TypeInvalid
}
