package cmp

import (
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestNewRoundCorrectness(t *testing.T) {
	n := 5

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	partyIds := make([]int, 5)
	for i := range partyIds {
		partyIds[i] = i
	}
	message := "hello"
	hashedMessage := HashMessageToScalar([]byte(message))

	configs := NewConfig(partyIds)
	sk := suite.Scalar().Zero()
	pk := configs[0].PK
	rounds := make([]Round, len(configs))
	for i, c := range configs {
		sk.Add(sk, c.Secret.ECDSA)
		rounds[i] = NewRound(c, func() {})
	}

	assert.True(t, suite.Point().Mul(sk, nil).Equal(pk))

	log.Info().Msg("start signing")

	msgs := make([]*Message, 0, n*(n-1))

	for roundNum := 0; roundNum < 5; roundNum++ {
		for _, r := range rounds {
			r.Log().Info().Msg("starting")
			for _, m := range msgs {
				err := r.Store(m)
				if err != nil {
					r.Log().Error().Err(err).Msg("failed to store")
				}
			}
		}

		msgs = msgs[:0]
		for rNum := 0; rNum < len(rounds); rNum++ {
			r := rounds[rNum]
			assert.True(t, r.CanExecute())

			newMsgs, err := r.GetMessagesOut()
			assert.NoError(t, err)
			msgs = append(msgs, newMsgs...)

			newR := r.NextRound()
			if newR == nil {
				break
			}
			rounds[rNum] = newR
			assert.NotNil(t, rounds[rNum])
		}

		// Encode and decode to simulate JSon
		for i := range msgs {
			m := msgs[i]
			mBin, err := json.Marshal(m)
			assert.NoError(t, err)
			m2 := new(Message)
			err = json.Unmarshal(mBin, m2)
			assert.NoError(t, err)
			msgs[i] = m2
		}
	}

	// Verify the sig is complete
	sig := msgs[0].Signature
	for _, m := range msgs {
		if !sig.R.Equal(m.Signature.R) {
			fmt.Print("err R")
		}
		if !sig.S.Equal(m.Signature.S) {
			fmt.Print("err S")
		}
		if !sig.M.Equal(m.Signature.M) {
			fmt.Print("err M")
		}
	}

	k := suite.Scalar().Zero()
	gamma := suite.Scalar().Zero()
	chi := suite.Scalar().Zero()

	for _, r := range rounds {
		r5 := r.(*round5)
		k.Add(k, r5.k)
		gamma.Add(gamma, r5.gamma)
		chi.Add(chi, r5.chi)
	}

	assert.True(t, suite.Scalar().Mul(sk, k).Equal(chi), "chi = k sk")

	kInv := suite.Scalar().Inv(k)
	R := suite.Point().Mul(kInv, nil)
	Gamma := suite.Point().Mul(gamma, nil)

	Rx := GetXCoord(R)
	sigComputed := suite.Scalar().Mul(sk, Rx)
	sigComputed.Add(sigComputed, hashedMessage)
	sigComputed.Mul(sigComputed, k)
	assert.True(t, sigComputed.Equal(sig.S))

	for _, r := range rounds {
		r5 := r.(*round5)

		assert.True(t, R.Equal(r5.R))
		assert.True(t, Gamma.Equal(r5.Gamma))
	}

	assert.True(t, msgs[0].Signature.Verify(pk))
}
