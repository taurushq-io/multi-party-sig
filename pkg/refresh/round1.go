package refresh

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/message"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
)

type round1 struct {
	session *session.Session

	thisParty *Party
	parties   map[uint32]*Party

	paillierSecret *paillier.SecretKey

	x *curve.Scalar // secret generated during keygen

	y *curve.Scalar // ElGamal secret

	p, q, phi, lambda *big.Int

	// receivedShares are the decrypted shares received from each party
	receivedShares map[uint32]*curve.Scalar

	// sentShares are the shares we send to other parties
	sentShares map[uint32]*curve.Scalar

	schRandA map[uint32]*curve.Scalar
	schRandB *curve.Scalar
}

func (round *round1) ProcessMessage(msg message.Message) error {
	// In the first round, no messages are expected.
	return nil
}

func (round *round1) GenerateMessages() ([]*message.Message, error) {
	var n, s, t *big.Int
	// generate N = p*q
	round.p, round.q, n, round.phi = sample.Paillier()
	round.thisParty.PaillierPublic = paillier.NewPublicKey(n)
	round.paillierSecret = paillier.NewSecretKey(round.phi, round.thisParty.PaillierPublic)

	// generate s, t=s^lambda
	s, t, round.lambda = sample.Pedersen(n, round.phi)

	// y for ElGamal
	round.y = curve.NewScalarRandom()
	Y := curve.NewIdentityPoint().ScalarBaseMult(round.y)

	// Schnorr commitment y
	round.schRandB = curve.NewScalarRandom()
	B := curve.NewIdentityPoint().ScalarBaseMult(round.schRandB)

	msg2 := message2{
		X:   make(map[uint32]*curve.Point),
		A:   make(map[uint32]*curve.Point),
		Y:   Y,
		B:   B,
		N:   n,
		S:   s,
		T:   t,
		Rho: make([]byte, 32),
		U:   make([]byte, 32),
	}

	// Sample x, X, a, A
	i := 0
	xs := randomZeroSum(round.session.N())
	for j := range round.parties {
		// assign share and public
		round.sentShares[j] = xs[i]
		msg2.X[j] = curve.NewIdentityPoint().ScalarBaseMult(xs[i])

		round.schRandA[j] = curve.NewScalarRandom()
		msg2.A[j] = curve.NewIdentityPoint().ScalarBaseMult(round.schRandA[j])
		i++
	}

	// sample uᵢ and {ρᵢ}
	_, err := rand.Read(msg2.Rho)
	if err != nil {
		return nil, fmt.Errorf("sample rho: %w", err)
	}
	_, err = rand.Read(msg2.U)
	if err != nil {
		return nil, fmt.Errorf("sample u: %w", err)
	}

	// commit to message 2
	V, err := msg2.Hash(round.session, round.session.SelfID())
	if err != nil {
		return nil, fmt.Errorf("hash msg2: %w", err)
	}
	msg1 := message1{CommitMessage2: V}

	round.thisParty.message1 = &msg1
	round.thisParty.message2 = &msg2

	fmt.Println(msg1)

	return nil, nil
}

func (round *round1) RequiredMessageCount() uint32 {
	return round.session.N()
}
func (round *round1) MessageType() message.Type {
	return message.Type(pb.Type_value["Refresh1"])
}

func (round *round1) IsProcessed(id uint32) bool {
	if _, ok := round.parties[id]; !ok {
		return false
	}
	return round.parties[id].Messages[round.MessageType()] == nil
}

func randomZeroSum(n uint32) []*curve.Scalar {
	x := make([]*curve.Scalar, n)
	sum := curve.NewScalar()
	for j := uint32(0); j < n-1; j++ {
		x[j] = curve.NewScalarRandom()
		sum.Add(sum, x[j])
	}
	sum.Negate(sum)
	x[n] = sum
	return x
}
