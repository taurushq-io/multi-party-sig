package taproot

import (
	"crypto/rand"
	"crypto/sha256"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAdaptorSerialize(t *testing.T) {
	for i := 0; i < 10; i++ {
		steak := sha256.New()
		steak.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF, byte(i)})
		steakHash := steak.Sum(nil)

		sk, pk, err := GenKey(rand.Reader)
		require.NoError(t, err)

		sig, err := sk.Sign(rand.Reader, steakHash)
		require.NoError(t, err)
		require.True(t, pk.Verify(sig, steakHash))

		R, err := curve.Secp256k1{}.LiftX(sig[:32])
		require.NoError(t, err)

		var z curve.Secp256k1Scalar
		err = z.UnmarshalBinary(sig[32:])
		require.NoError(t, err)

		adaptor := NewAdaptorSignature(*R, z)
		serialized := adaptor.Serialize()
		require.Equal(t, byte(2), serialized[0])
		require.Equal(t, []byte(sig), serialized[1:])
	}
}

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
