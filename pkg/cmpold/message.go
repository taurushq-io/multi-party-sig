package cmpold

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/zkold"
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
		Proof *zkold.EncryptionInRangeProof
		K, G  *paillier.Ciphertext
	}

	msg2 struct {
		D, F, DHat, FHat *paillier.Ciphertext
		ProofGamma       *zkold.AffineGroupCommitmentRange
		ProofX           *zkold.AffineGroupCommitmentRange
		ProofLog         *zkold.Log
		Gamma            kyber.Point
	}

	msg3 struct {
		Proof *zkold.Log

		DeltaScalar kyber.Scalar
		DeltaPoint  kyber.Point
	}

	msg4 struct {
		Sigma kyber.Scalar
	}
)
