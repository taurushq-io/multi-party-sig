package keygen

import (
	"errors"

	"github.com/taurusgroup/cmp-ecdsa/pb"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	zksch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
)

type round3 struct {
	*round2

	rid []byte // rid = ⊕ᵢ ridᵢ
}

func (round *round3) ProcessMessage(msg *pb.Message) error {
	var err error

	j := msg.GetFromID()
	partyJ := round.parties[j]

	body := msg.GetKeygen2()

	rid := body.GetRid()
	if len(rid) != params.SecBytes {
		return errors.New("rid is wrong length")
	}

	var X, A *curve.Point
	if X, err = body.GetX().Unmarshal(); err != nil {
		return err
	}
	if A, err = body.GetA().Unmarshal(); err != nil {
		return err
	}

	commitment := partyJ.commitment
	decommitment := body.GetU()
	if !round.H.Decommit(j, commitment, decommitment, rid, X, A) {
		return errors.New("failed to decommit")
	}

	partyJ.rid = rid
	partyJ.X = X
	partyJ.A = A

	partyJ.keygen2 = body

	return nil
}

func (round *round3) GenerateMessages() ([]*pb.Message, error) {
	// rid = ⊕ⱼ ridⱼ
	round.rid = make([]byte, params.SecBytes)
	for _, partyJ := range round.parties {
		for i := 0; i < params.SecBytes; i++ {
			round.rid[i] ^= partyJ.rid[i]
		}
	}

	// include the agreed upon rid in the session
	if _, err := round.H.Write(round.rid); err != nil {
		return nil, err
	}

	// Schnorr proof
	partyI := round.thisParty
	proofX, err := zksch.Prove(round.H.CloneWithID(round.SelfID), partyI.A, partyI.X, round.p.a, round.p.PrivateECDSA)
	if err != nil {
		return nil, errors.New("failed to generate schnorr")
	}

	return []*pb.Message{{
		Type:      pb.MessageType_TypeKeygen3,
		From:      round.SelfID,
		Broadcast: pb.Broadcast_Basic,
		Keygen3: &pb.Keygen3{
			SchX: pb.NewScalar(proofX),
		},
	}}, nil
}

func (round *round3) Finalize() (round.Round, error) {
	return &output{
		round3: round,
		X:      curve.NewIdentityPoint(),
	}, nil
}

func (round *round3) MessageType() pb.MessageType {
	return pb.MessageType_TypeKeygen2
}

func (round *round3) IsProcessed(id party.ID) bool {
	return round.parties[id].keygen2 != nil
}
