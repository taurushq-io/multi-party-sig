package presign

import (
	"fmt"
	mrand "math/rand"
	"reflect"
	"sync"
	"testing"

	"github.com/cronokirby/safenum"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/config"
	"golang.org/x/crypto/sha3"
)

var (
	oneNat      = new(safenum.Nat).SetUint64(1)
	oneInt      = new(safenum.Int).SetNat(oneNat)
	minusOneInt = new(safenum.Int).SetNat(oneNat).Neg(1)

	N               = 3
	T               = N - 1
	group           = curve.Secp256k1{}
	configs         map[party.ID]*config.Config
	partyIDs        party.IDSlice
	culprit, victim party.ID
	messageHash     []byte
)

func init() {
	source := mrand.New(mrand.NewSource(1))
	pl := pool.NewPool(0)
	defer pl.TearDown()
	configs = test.GenerateConfig(group, N, T, source, pl)
	partyIDs = make([]party.ID, 0, N)
	for id, c := range configs {
		configs[id], _ = c.DeriveChild(0)
		partyIDs = append(partyIDs, id)
	}
	culprit = partyIDs[0]
	victim = partyIDs[1]

	messageHash = make([]byte, 64)
	sha3.ShakeSum128(messageHash, []byte("hello"))
}

func TestRound(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	var err error
	rounds := make(map[party.ID]round.Round, N)
	for id, c := range configs {
		rounds[id], _, err = StartSign(pl, c, partyIDs, messageHash)()
		require.NoError(t, err, "round creation should not result in an error")
	}

	for {
		err, done := test.Rounds(group, rounds, "", nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}
	for id, r := range rounds {
		assert.IsType(t, &round.Output{}, r)
		signature, ok := r.(*round.Output).Result.(*ecdsa.Signature)
		assert.True(t, ok, "result should *ecdsa.Signature")
		assert.True(t, signature.Verify(configs[id].PublicPoint(), messageHash))
	}
}

type ChangeDeltaRound4 struct{}

func (ChangeDeltaRound4) ModifyBefore(round.Round) {}

func (ChangeDeltaRound4) ModifyAfter(rNext round.Round) {
	r, ok := rNext.(*presign4)
	if !ok {
		return
	}
	oneScalar := r.Group().NewScalar().SetNat(oneNat)
	r.DeltaShares[r.SelfID()].Sub(oneScalar)
}

func (ChangeDeltaRound4) ModifyContent(rNext round.Round, _ party.ID, content round.Content) {
	m, ok := content.(*message4)
	if !ok {
		return
	}
	r, ok := rNext.(*presign4)
	if !ok {
		return
	}
	oneScalar := r.Group().NewScalar().SetNat(oneNat)
	m.DeltaShare.Sub(oneScalar)
}

type ChangeGammaShare struct{}

func (ChangeGammaShare) ModifyBefore(rPrevious round.Round) {
	switch r := rPrevious.(type) {
	case *presign3:
		r.GammaShare.Add(r.GammaShare, minusOneInt, -1)
	default:
	}
}

func (ChangeGammaShare) ModifyAfter(rNext round.Round) {
	switch r := rNext.(type) {
	case *presign3:
		r.GammaShare.Add(r.GammaShare, oneInt, -1)
	default:
	}
}

func (ChangeGammaShare) ModifyContent(round.Round, party.ID, round.Content) {}

type ChangeChiX struct{}

func (ChangeChiX) ModifyBefore(rPrevious round.Round) {
	switch r := rPrevious.(type) {
	case *presign3:
		minusOne := r.Group().NewScalar().SetNat(oneNat).Negate()
		r.SecretECDSA.Add(minusOne)
	default:
	}
}

func (ChangeChiX) ModifyAfter(rNext round.Round) {
	switch r := rNext.(type) {
	case *presign3:
		one := r.Group().NewScalar().SetNat(oneNat)
		r.SecretECDSA.Add(one)
	default:
	}
}

func (ChangeChiX) ModifyContent(round.Round, party.ID, round.Content) {}

type ChangeChiK struct{}

func (ChangeChiK) ModifyBefore(rPrevious round.Round) {
	switch r := rPrevious.(type) {
	case *presign3:
		minusOne := r.Group().NewScalar().SetNat(oneNat).Negate()
		r.KShare.Add(minusOne)
	case *presign4:
		g := r.Group().NewScalar().SetNat(r.GammaShare.Mod(r.Group().Order()))
		r.DeltaShares[r.SelfID()] = g.Add(r.DeltaShares[r.SelfID()])
	case *presign7:
		b := r.Group().NewBasePoint()
		r.PublicKey = r.PublicKey.Add(b)
	default:
	}
}

func (ChangeChiK) ModifyAfter(rNext round.Round) {
	switch r := rNext.(type) {
	case *presign3:
		one := r.Group().NewScalar().SetNat(oneNat)
		r.KShare = one.Add(r.KShare)
	case *presign7:
		b := r.Group().NewBasePoint()
		r.PublicKey = r.PublicKey.Sub(b)
	default:
	}
}

func (ChangeChiK) ModifyContent(rNext round.Round, _ party.ID, content round.Content) {
	r, okR := rNext.(*presign4)
	c, okC := content.(*message4)
	if !okR || !okC {
		return
	}
	g := r.Group().NewScalar().SetNat(r.GammaShare.Mod(r.Group().Order()))
	c.DeltaShare = g.Add(c.DeltaShare)
}

type ChangeChi struct{}

func (ChangeChi) ModifyBefore(rPrevious round.Round) {
	switch r := rPrevious.(type) {
	case *presign4:
		one := r.Group().NewScalar().SetNat(oneNat)
		r.ChiShare = one.Add(r.ChiShare)
	//case *presign7:
	//	b := r.Group().NewBasePoint()
	//	r.PublicKey = r.PublicKey.Add(b)
	default:
	}
}

func (ChangeChi) ModifyAfter(rNext round.Round) {
	//switch r := rNext.(type) {
	//case *presign3:
	//one := r.Group().NewScalar().SetNat(oneNat)
	//r.KShare = one.Add(r.KShare)
	//case *presign7:
	//	b := r.Group().NewBasePoint()
	//	r.PublicKey = r.PublicKey.Sub(b)
	//default:
	//}
}

func (ChangeChi) ModifyContent(rNext round.Round, _ party.ID, content round.Content) {
	r, okR := rNext.(*presign4)
	c, okC := content.(*message4)
	if !okR || !okC {
		return
	}
	g := r.Group().NewBasePoint()
	c.ElGamalChi.M = g.Add(c.ElGamalChi.M)
}

func TestRoundFail(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	tests := []test.Rule{
		ChangeGammaShare{},
		ChangeDeltaRound4{},
		ChangeChiX{},
		ChangeChiK{},
		ChangeChi{}}
	for _, testCase := range tests {
		t.Run(reflect.TypeOf(testCase).String(), func(t *testing.T) {
			rounds := make(map[party.ID]round.Round, N)
			for id, c := range configs {
				rounds[id], _, _ = StartSign(pl, c, partyIDs, messageHash[:])()
			}
			for {
				err, done := test.Rounds(group, rounds, culprit, testCase)
				if err != nil || done {
					if err != nil {
						t.Log(err)
					}
					assert.Error(t, err, "round should terminate with error")
					break
				}
			}
		})
	}
}

func TestProtocol(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	ps := map[party.ID]*protocol.Handler{}

	handleMessage := func(msg *protocol.Message) {
		if msg == nil {
			return
		}
		for id, p := range ps {
			if msg.IsFor(id) {
				err := p.Update(msg)
				assert.NoError(t, err)
			}
		}
	}

	wg := new(sync.WaitGroup)
	getMessages := func(p *protocol.Handler) {
		for msg := range p.Listen() {
			handleMessage(msg)
		}
		fmt.Println("done")
		wg.Done()
	}

	for id, c := range configs {
		p, err := protocol.NewHandler(StartSign(pl, configs[id], c.PartyIDs(), messageHash))
		require.NoError(t, err)
		ps[id] = p
	}
	for _, p := range ps {
		wg.Add(1)
		go getMessages(p)
	}
	wg.Wait()

	for id, p := range ps {
		r, err := p.Result()
		assert.NoError(t, err)
		assert.IsType(t, &ecdsa.Signature{}, r)
		signature := r.(*ecdsa.Signature)
		assert.True(t, signature.Verify(configs[id].PublicPoint(), messageHash))
	}
}
