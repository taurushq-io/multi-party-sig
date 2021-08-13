package taproot

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignatureVerification(t *testing.T) {
	for i := 0; i < 10; i++ {
		steak := sha256.New()
		steak.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF, byte(i)})
		steakHash := steak.Sum(nil)

		sk, pk, err := GenKey(rand.Reader)
		require.NoError(t, err)

		sig1, err := sk.Sign(rand.Reader, steakHash)
		require.NoError(t, err)
		require.True(t, pk.Verify(sig1, steakHash))

		sig2, err := sk.Sign(nil, steakHash)
		require.NoError(t, err)
		require.True(t, pk.Verify(sig2, steakHash))
	}

}
