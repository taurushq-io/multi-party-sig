package sign

import "errors"

var (
	ErrRound2ZKEnc                       = errors.New("failed to validate enc proof")
	ErrRound3ZKAffGDeltaMtA              = errors.New("failed to validate affg proof for Delta MtA")
	ErrRound3ZKAffGChiMtA                = errors.New("failed to validate affg proof for Chi MtA")
	ErrRound3ZKLog                       = errors.New("failed to validate log proof")
	ErrRound3EchoHash                    = errors.New("received echo hash is different")
	ErrRound4ZKLog                       = errors.New("failed to validate log proof")
	ErrRound4BigDelta                    = errors.New("computed Δ is inconsistent with [δ]G")
	ErrRoundOutputSigmaZero              = errors.New("sigma is 0")
	ErrRoundOutputValidateSigFailedECDSA = errors.New("failed to validate signature with Go stdlib")
	ErrRoundOutputValidateSigFailed      = errors.New("failed to validate signature")
	ErrRoundOutputNilSig                 = errors.New("signature is nil")
)
