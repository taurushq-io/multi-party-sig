package cmp

import (
	"github.com/taurusgroup/cmp-ecdsa/paillier"
	"github.com/taurusgroup/cmp-ecdsa/zk"
	"go.dedis.ch/kyber/v3"
)

type Message struct {
	From, To  int
	Message   string
	Msg1      *msg1
	Msg2      *msg2
	Msg3      *msg3
	Msg4      *msg4
	Signature *Signature
}

type (
	msg1 struct {
		Proof *zk.EncryptionInRangeProof
		K, G  *paillier.Ciphertext
	}

	msg2 struct {
		D, F, DHat, FHat *paillier.Ciphertext
		ProofGamma       *zk.AffineGroupCommitmentRange
		ProofX           *zk.AffineGroupCommitmentRange
		ProofLog         *zk.Log
		Gamma            kyber.Point
	}

	msg3 struct {
		Proof *zk.Log

		DeltaScalar kyber.Scalar
		DeltaPoint  kyber.Point
	}

	msg4 struct {
		Sigma kyber.Scalar
	}
)
