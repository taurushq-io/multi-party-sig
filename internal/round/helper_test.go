package round_test

import (
	"testing"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func TestNewSession(t *testing.T) {
	RNumber := round.Number(5)
	T := 20
	N := 26
	partyIDs := test.PartyIDs(N)
	selfID := partyIDs[0]
	tests := []struct {
		name        string
		roundNumber round.Number
		selfID      party.ID
		partyIDs    []party.ID
		threshold   int
		group       curve.Curve
		wantErr     bool
	}{
		{
			"-1 t",
			RNumber,
			selfID,
			partyIDs,
			-1,
			curve.Secp256k1{},
			true,
		},
		{
			"invalid selfID",
			RNumber,
			"",
			partyIDs,
			T,
			curve.Secp256k1{},
			true,
		},
		{
			"duplicate selfID",
			RNumber,
			selfID,
			append(partyIDs, selfID),
			T,
			curve.Secp256k1{},
			true,
		},
		{
			"duplicate second ID",
			RNumber,
			selfID,
			append(partyIDs, partyIDs[1]),
			T,
			curve.Secp256k1{},
			true,
		},
		{
			"duplicate partyIDs",
			RNumber,
			selfID,
			append(partyIDs, partyIDs...),
			T,
			curve.Secp256k1{},
			true,
		},
		{
			"threshold N",
			RNumber,
			selfID,
			partyIDs,
			N,
			curve.Secp256k1{},
			true,
		},
		{
			"threshold T with T parties",
			RNumber,
			selfID,
			partyIDs[:T],
			T,
			curve.Secp256k1{},
			true,
		},
		{
			"no group",
			RNumber,
			selfID,
			partyIDs,
			T,
			curve.Secp256k1{},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := round.Info{
				ProtocolID:       "TEST",
				FinalRoundNumber: tt.roundNumber,
				SelfID:           tt.selfID,
				PartyIDs:         tt.partyIDs,
				Threshold:        tt.threshold,
				Group:            tt.group,
			}
			_, err := round.NewSession(info, nil, nil)
			if tt.wantErr == (err == nil) {
				t.Error(err)
			}
		})
	}
}
