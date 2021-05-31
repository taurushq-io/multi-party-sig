package paillier

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicKey_UnmarshalJSON(t *testing.T) {
	sk := NewSecretKey()
	pk := sk.PublicKey()
	d, err := json.Marshal(pk)
	require.NoError(t, err, "failed to marshal")
	var pk2 PublicKey
	err = json.Unmarshal(d, &pk2)
	require.NoError(t, err, "failed to unmarshal")
	assert.Equal(t, pk, &pk2, "different pk after unmarshal")
}

func TestSecretKey_UnmarshalJSON(t *testing.T) {
	sk := NewSecretKey()
	d, err := json.Marshal(sk)
	require.NoError(t, err, "failed to marshal")
	var sk2 SecretKey
	err = json.Unmarshal(d, &sk2)
	require.NoError(t, err, "failed to unmarshal")
	assert.Equal(t, sk, &sk2, "different sk after unmarshal")
}
