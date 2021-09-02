package keygen

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

func checkOutput(t *testing.T, configSender *ConfigSender, configReceiver *ConfigReceiver) {
	require.True(t, configSender.Public.Equal(configReceiver.Public))
	require.False(t, configSender.Public.IsIdentity())
	secret := configSender.Group().NewScalar().Set(configSender.SecretShare).Mul(configReceiver.SecretShare)
	public := secret.ActOnBase()
	require.True(t, public.Equal(configSender.Public))
}

func TestKeygen(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(2)

	rounds := make([]round.Session, 0, 2)
	fmt.Println("partyIDS", partyIDs)
	r0, err := StartKeygen(group, false, partyIDs[0], partyIDs[1], pl)(nil)
	require.NoError(t, err, "round creation should not result in an error")
	rounds = append(rounds, r0)
	r1, err := StartKeygen(group, true, partyIDs[1], partyIDs[0], pl)(nil)
	rounds = append(rounds, r1)
	require.NoError(t, err, "round creation should not result in an error")

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	resultRound0, ok := rounds[0].(*round.Output)
	require.True(t, ok)
	configSender, ok := resultRound0.Result.(*ConfigSender)
	require.True(t, ok)

	resultRound1, ok := rounds[1].(*round.Output)
	require.True(t, ok)
	configReceiver, ok := resultRound1.Result.(*ConfigReceiver)
	require.True(t, ok)

	checkOutput(t, configSender, configReceiver)
}
