package presign

import (
	"errors"
	"sort"
	"testing"

	"github.com/cronokirby/safenum"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/elgamal"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

var (
	oneNat      = new(safenum.Nat).SetUint64(1)
	oneInt      = new(safenum.Int).SetNat(oneNat)
	minusOneInt = new(safenum.Int).SetNat(oneNat).Neg(1)
)

type TestRule struct {
	BeforeFinalize func(rBefore round.Session)
	AfterFinalize  func(rNext round.Session)
	BeforeSend     func(rNext round.Session, to party.ID, content round.Content)
}

func (tr *TestRule) ModifyBefore(rBefore round.Session) {
	if rBefore.SelfID() != "a" {
		return
	}
	if tr.BeforeFinalize != nil {
		tr.BeforeFinalize(rBefore)
	}
}

func (tr *TestRule) ModifyAfter(rNext round.Session) {
	if rNext.SelfID() != "a" {
		return
	}
	if tr.AfterFinalize != nil {
		tr.AfterFinalize(rNext)
	}
}

func (tr *TestRule) ModifyContent(rNext round.Session, to party.ID, content round.Content) {
	if rNext.SelfID() != "a" {
		return
	}
	if tr.BeforeSend != nil {
		tr.BeforeSend(rNext, to, content)
	}
}

// failRule defines the rules that will abort at step 6 or step 7
type failRule struct {
	failedParites map[party.ID]struct{}
	changeStep    round.Number
	changeAfter   func(round.Session)
	changeContent func(round.Session, party.ID, round.Content)
	abortErr      string
}

func (f *failRule) ModifyBefore(r round.Session) {}

func (f *failRule) ModifyAfter(rNext round.Session) {
	if !f.hitRule(rNext.Number()-1, rNext.SelfID()) || f.changeAfter == nil {
		return
	}
	f.changeAfter(rNext)
}

func (f *failRule) ModifyContent(rNext round.Session, to party.ID, content round.Content) {
	if !f.hitRule(rNext.Number()-1, rNext.SelfID()) || f.changeContent == nil {
		return
	}
	f.changeContent(rNext, to, content)
}

func (f *failRule) HitParty(partyId party.ID) bool {
	_, hit := f.failedParites[partyId]
	return hit
}

func (f *failRule) GetCorruptPartyIDsAndAbortErr() ([]party.ID, string) {
	partyIDs := make(party.IDSlice, 0, len(f.failedParites))
	for key, _ := range f.failedParites {
		partyIDs = append(partyIDs, key)
	}
	sort.Sort(partyIDs)
	return partyIDs, f.abortErr
}

func (f *failRule) hitRule(step round.Number, partyId party.ID) bool {
	if step != f.changeStep {
		return false
	}
	return f.HitParty(partyId)
}

// newFailRule makes rules to fail the presign process at given 'step',
// and adversarial index are given by 'failedParties'
func newFailRule(step int, allParties party.IDSlice, failedParties ...int) (*failRule, error) {
	failedPartyIDs := make(map[party.ID]struct{})
	for _, idx := range failedParties {
		id := allParties[idx]
		failedPartyIDs[id] = struct{}{}
	}
	var (
		changeStep    round.Number
		changeAfter   func(round.Session)
		changeContent func(round.Session, party.ID, round.Content)
		abortErr      string
	)
	switch step {
	case 6:
		// in this case, we broadcast the wrong delta value at step 3
		changeStep = 3
		changeContent = func(rNext round.Session, to party.ID, content round.Content) {
			body, ok := content.(*broadcast4)
			if !ok || body == nil {
				return
			}
			body.DeltaShare = body.DeltaShare.Add(group.NewScalar().SetNat(oneNat))
		}
		abortErr = "abort1: detected culprit"
		break
	case 7:
		// in this case, we generate the wrong chi value and its ElGamal commitment at step 3
		// and broadcast the wrong ElGamal conmmitment of chi
		changeStep = 3
		changeAfter = func(rNext round.Session) {
			realRound, ok := rNext.(*presign4)
			if !ok || realRound == nil {
				return
			}
			realRound.ChiShare = realRound.ChiShare.Add(group.NewScalar().SetNat(oneNat))
			ElGamalChi, ElGamalChiNonce := elgamal.Encrypt(realRound.ElGamal[realRound.SelfID()], realRound.ChiShare)
			realRound.ElGamalChiNonce = ElGamalChiNonce
			realRound.ElGamalChi = map[party.ID]*elgamal.Ciphertext{realRound.SelfID(): ElGamalChi}
		}
		changeContent = func(rNext round.Session, to party.ID, content round.Content) {
			body, ok := content.(*broadcast4)
			if !ok || body == nil {
				return
			}
			realRound, ok := rNext.(*presign4)
			if !ok || realRound == nil {
				return
			}
			body.ElGamalChi = realRound.ElGamalChi[realRound.SelfID()]
		}
		abortErr = "abort2: detected culprit"
		break
	default:
		return nil, errors.New("Unknow fail step to generate rule")
	}
	return &failRule{
		failedParites: failedPartyIDs,
		changeStep:    changeStep,
		changeAfter:   changeAfter,
		changeContent: changeContent,
		abortErr:      abortErr,
	}, nil
}

func checkAbortOutput(t *testing.T, output []round.Session, rule *failRule) {
	expectedCulprits, abortErr := rule.GetCorruptPartyIDsAndAbortErr()
	for _, r := range output {
		require.IsType(t, &round.Abort{}, r, "expected abort round")
		abortRound := r.(*round.Abort)
		assert.EqualError(t, abortRound.Err, abortErr)
		if !rule.HitParty(abortRound.SelfID()) {
			assert.Equal(t, expectedCulprits, abortRound.Culprits)
		}
	}
}

func TestCommonFail(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	N := 4
	T := N - 1
	configs, partyIDs, _ := generateTNPartiesAndKeys(t, T, N, T, pl)

	tests := []struct {
		name string
		r    TestRule
	}{
		{
			"round 3 sub one from delta share",
			TestRule{
				AfterFinalize: func(rNext round.Session) {
					if r, ok := rNext.(*presign4); ok {
						oneScalar := r.Group().NewScalar().SetNat(oneNat)
						r.DeltaShares[r.SelfID()] = r.Group().NewScalar().Set(r.DeltaShares[r.SelfID()]).Sub(oneScalar)
					}
				},
				BeforeSend: func(rNext round.Session, to party.ID, content round.Content) {
					r, okR := rNext.(*presign4)
					c, okC := content.(*broadcast4)
					if okR || okC {
						oneScalar := r.Group().NewScalar().SetNat(oneNat)
						c.DeltaShare = r.Group().NewScalar().Set(c.DeltaShare).Sub(oneScalar)
					}
				},
			},
		},
		{
			"round 3 modify gamma for delta",
			TestRule{
				BeforeFinalize: func(rPrevious round.Session) {
					if r, ok := rPrevious.(*presign3); ok {
						r.GammaShare = new(safenum.Int).Add(r.GammaShare, minusOneInt, -1)
					}
				},
				AfterFinalize: func(rNext round.Session) {
					if r, ok := rNext.(*presign4); ok {
						r.GammaShare = new(safenum.Int).Add(r.GammaShare, oneInt, -1)
					}
				},
			},
		},
		{
			"round 3 modify x to change chi",
			TestRule{
				BeforeFinalize: func(rPrevious round.Session) {
					switch r := rPrevious.(type) {
					case *presign3:
						minusOne := r.Group().NewScalar().SetNat(oneNat).Negate()
						r.SecretECDSA = minusOne.Add(r.SecretECDSA)
					default:
					}
				},
				AfterFinalize: func(rNext round.Session) {
					switch r := rNext.(type) {
					case *presign4:
						one := r.Group().NewScalar().SetNat(oneNat)
						r.SecretECDSA = one.Add(r.SecretECDSA)
					default:
					}
				},
			},
		},
		{
			"round 3 modify chi force abort",
			TestRule{
				AfterFinalize: func(rNext round.Session) {
					if r, ok := rNext.(*presign3); ok {
						r.SecretECDSA = r.Group().NewScalar().SetNat(oneNat).Add(r.SecretECDSA)
					}
				},
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			rounds := make([]round.Session, 0, N)
			for _, c := range configs {
				r, err := StartPresign(c, partyIDs, messageHash[:], pl)(nil)
				require.NoError(t, err)
				rounds = append(rounds, r)
			}
			for {
				err, done := test.Rounds(rounds, &testCase.r)
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

func TestPresignT1N2FailStep6CorruptParty0(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	configs, partyIDs, _ := generateTNPartiesAndKeys(t, 1, 2, 2, pl)
	rule, err := newFailRule(6, partyIDs, 0)
	assert.NoError(t, err)
	output := presignWithTNParties(t, configs, partyIDs, rule, nil, pl)
	checkAbortOutput(t, output, rule)
}

func TestPresignT1N2FailStep6CorruptParty1(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	configs, partyIDs, _ := generateTNPartiesAndKeys(t, 1, 2, 2, pl)
	rule, err := newFailRule(6, partyIDs, 1)
	assert.NoError(t, err)
	output := presignWithTNParties(t, configs, partyIDs, rule, nil, pl)
	checkAbortOutput(t, output, rule)
}

func TestPresignT1N2FailStep6CorruptParty01(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	configs, partyIDs, _ := generateTNPartiesAndKeys(t, 1, 2, 2, pl)
	rule, err := newFailRule(6, partyIDs, 0, 1)
	assert.NoError(t, err)
	output := presignWithTNParties(t, configs, partyIDs, rule, nil, pl)
	checkAbortOutput(t, output, rule)
}

func TestPresignT2N5FailStep6CorruptParty0(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	configs, partyIDs, _ := generateTNPartiesAndKeys(t, 2, 5, 3, pl)
	rule, err := newFailRule(6, partyIDs, 0)
	assert.NoError(t, err)
	output := presignWithTNParties(t, configs, partyIDs, rule, nil, pl)
	checkAbortOutput(t, output, rule)
}

func TestPresignT2N5FailStep6CorruptParty02(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	configs, partyIDs, _ := generateTNPartiesAndKeys(t, 2, 5, 3, pl)
	rule, err := newFailRule(6, partyIDs, 0, 2)
	assert.NoError(t, err)
	output := presignWithTNParties(t, configs, partyIDs, rule, nil, pl)
	checkAbortOutput(t, output, rule)
}

func TestPresignT1N2FailStep7CorruptParty0(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	configs, partyIDs, _ := generateTNPartiesAndKeys(t, 1, 2, 2, pl)
	rule, err := newFailRule(7, partyIDs, 0)
	assert.NoError(t, err)
	output := presignWithTNParties(t, configs, partyIDs, rule, nil, pl)
	checkAbortOutput(t, output, rule)
}

func TestPresignT1N2FailStep7CorruptParty1(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	configs, partyIDs, _ := generateTNPartiesAndKeys(t, 1, 2, 2, pl)
	rule, err := newFailRule(7, partyIDs, 1)
	assert.NoError(t, err)
	output := presignWithTNParties(t, configs, partyIDs, rule, nil, pl)
	checkAbortOutput(t, output, rule)
}

func TestPresignT1N2FailStep7CorruptParty01(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	configs, partyIDs, _ := generateTNPartiesAndKeys(t, 1, 2, 2, pl)
	rule, err := newFailRule(7, partyIDs, 0, 1)
	assert.NoError(t, err)
	output := presignWithTNParties(t, configs, partyIDs, rule, nil, pl)
	checkAbortOutput(t, output, rule)
}

func TestPresignT2N5FailStep7CorruptParty0(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	configs, partyIDs, _ := generateTNPartiesAndKeys(t, 2, 5, 3, pl)
	rule, err := newFailRule(7, partyIDs, 0)
	assert.NoError(t, err)
	output := presignWithTNParties(t, configs, partyIDs, rule, nil, pl)
	checkAbortOutput(t, output, rule)
}

func TestPresignT2N5FailStep7CorruptParty02(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	configs, partyIDs, _ := generateTNPartiesAndKeys(t, 2, 5, 3, pl)
	rule, err := newFailRule(7, partyIDs, 0, 2)
	assert.NoError(t, err)
	output := presignWithTNParties(t, configs, partyIDs, rule, nil, pl)
	checkAbortOutput(t, output, rule)
}
