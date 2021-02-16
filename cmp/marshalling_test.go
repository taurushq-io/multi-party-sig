package cmp

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_msg2_UnmarshalJSON(t *testing.T) {

	msg := &msg2{
		Gamma: suite.Point().Pick(suite.RandomStream()),
	}

	d, err := json.Marshal(msg)
	assert.NoError(t, err)

	newMsg := new(msg2)
	err = json.Unmarshal(d, newMsg)
	assert.NoError(t, err)

	assert.True(t, newMsg.Gamma.Equal(msg.Gamma))
}

func Test_msg3_UnmarshalJSON(t *testing.T) {
	msg := &msg3{
		DeltaPoint:  suite.Point().Pick(suite.RandomStream()),
		DeltaScalar: suite.Scalar().Pick(suite.RandomStream()),
	}

	d, err := json.Marshal(msg)
	assert.NoError(t, err)

	newMsg := new(msg3)
	err = json.Unmarshal(d, newMsg)
	assert.NoError(t, err)

	assert.True(t, newMsg.DeltaPoint.Equal(msg.DeltaPoint))
	assert.True(t, newMsg.DeltaScalar.Equal(msg.DeltaScalar))
}

func Test_msg4_UnmarshalJSON(t *testing.T) {
	msg := &msg4{
		Sigma: suite.Scalar().Pick(suite.RandomStream()),
	}

	d, err := json.Marshal(msg)
	assert.NoError(t, err)

	newMsg := new(msg4)
	err = json.Unmarshal(d, newMsg)
	assert.NoError(t, err)

	assert.True(t, newMsg.Sigma.Equal(msg.Sigma))
}

func Test_Sig_UnmarshalJSON(t *testing.T) {
	msg := &Signature{
		R: suite.Point().Pick(suite.RandomStream()),
		S: suite.Scalar().Pick(suite.RandomStream()),
		M: suite.Scalar().Pick(suite.RandomStream()),
	}

	d, err := json.Marshal(msg)
	assert.NoError(t, err)

	newMsg := new(Signature)
	err = json.Unmarshal(d, newMsg)
	assert.NoError(t, err)

	assert.True(t, newMsg.R.Equal(msg.R))
	assert.True(t, newMsg.S.Equal(msg.S))
	assert.True(t, newMsg.M.Equal(msg.M))
}
