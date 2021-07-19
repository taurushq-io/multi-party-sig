package refresh

import "errors"

var (
	ErrRound1SampleRho       = errors.New("failed to sample Rho")
	ErrRound1Commit          = errors.New("failed to commit")
	ErrRound3EchoHash        = errors.New("received different echo hash")
	ErrRound4VSSConstant     = errors.New("vss polynomial has incorrect constant")
	ErrRound4VSSDegree       = errors.New("vss polynomial has incorrect degree")
	ErrRound4Decommit        = errors.New("failed to decommit")
	ErrRound5Decrypt         = errors.New("decrypted share is not in correct range")
	ErrRound5VSS             = errors.New("failed to validate VSS share")
	ErrRound5ZKMod           = errors.New("failed to validate mod proof")
	ErrRound5ZKPrm           = errors.New("failed to validate prm proof")
	ErrRoundOutputZKSch      = errors.New("failed to validate schnorr proof for received share")
	ErrRoundOutputNilSession = errors.New("session is nil")
)
