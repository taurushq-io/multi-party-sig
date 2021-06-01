package party

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

func TestPublic_MarshalJSON(t *testing.T) {
	ssid := make([]byte, params.HashBytes)
	_, _ = rand.Read(ssid)
	sk := paillier.NewSecretKey()
	pk := sk.PublicKey()
	ped, _ := sk.GeneratePedersen()
	p := Public{
		ID:       RandomIDs(1)[0],
		SSID:     ssid,
		ECDSA:    curve.NewIdentityPoint().ScalarBaseMult(curve.NewScalarRandom()),
		Paillier: pk,
		Pedersen: ped,
	}

	data, err := json.Marshal(p)
	require.NoError(t, err, "marshalling failed")
	p2 := Public{}
	err = json.Unmarshal(data, &p2)
	require.NoError(t, err, "unmarshalling failed")
	require.Equal(t, p, p2, "unmarshalling gave different result")
	fmt.Println(string(data))
}
