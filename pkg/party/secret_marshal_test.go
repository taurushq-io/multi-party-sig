package party

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

func TestSecret_MarshalJSON(t *testing.T) {
	rid := make([]byte, params.SecBytes)
	_, _ = rand.Read(rid)
	s := Secret{
		ID:       "bal",
		ECDSA:    curve.NewScalarRandom(),
		Paillier: paillier.NewSecretKey(),
		RID:      rid,
	}

	data, err := json.Marshal(s)
	require.NoError(t, err, "marshalling failed")
	s2 := Secret{}
	err = json.Unmarshal(data, &s2)
	require.NoError(t, err, "unmarshalling failed")
	require.Equal(t, s, s2, "unmarshalling gave different result")
}
