package session

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSession_MarshalJSON(t *testing.T) {
	N := 5
	T := 2
	sessions := FakeKeygen(N, T)
	s := sessions[0]
	data, err := json.Marshal(s)
	require.NoError(t, err, "marshalling failed")
	s2 := &KeygenSession{}
	err = json.Unmarshal(data, s2)
	pretty := bytes.NewBuffer(nil)
	json.Indent(pretty, data, "  ", "\t")
	fmt.Println(pretty)
	require.NoError(t, err, "unmarshalling failed")
	assert.NoError(t, s.Validate(), "s failed to validate")
	assert.NoError(t, s2.Validate(), "s2 failed to validate")
	assert.True(t, s.PublicKey().Equal(s2.PublicKey()), "public keys should be equal")
	assert.Equal(t, s, s2, "unmarshalling gave different result")
}
