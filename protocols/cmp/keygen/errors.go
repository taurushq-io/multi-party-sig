package keygen

import "errors"

var (
	ErrRound1SampleRho   = errors.New("failed to sample Rho")
	ErrRound1SampleC     = errors.New("failed to sample c")
	ErrRound1Commit      = errors.New("failed to commit")
	ErrRound3EchoHash    = errors.New("received different echo hash")
	ErrRound3VSSConstant = errors.New("vss polynomial has incorrect constant")
	ErrRound3VSSDegree   = errors.New("vss polynomial has incorrect degree")
	ErrRound3Decommit    = errors.New("failed to decommit")
	ErrRound4Decrypt     = errors.New("decrypted share is not in correct range")
	ErrRound4VSS         = errors.New("failed to validate VSS share")
	ErrRound4ZKMod       = errors.New("failed to validate mod proof")
	ErrRound4ZKPrm       = errors.New("failed to validate prm proof")
	ErrRoundOutputZKSch  = errors.New("failed to validate schnorr proof for received share")
)
