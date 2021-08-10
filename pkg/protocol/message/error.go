package message

// Error indicates that the message does not pass validation.
type Error string

const (
	ErrDuplicate          Error = "message was already handled"
	ErrUnknownSender      Error = "unknown sender"
	ErrNilContent         Error = "content is nil"
	ErrWrongSSID          Error = "SSID mismatch"
	ErrWrongProtocolID    Error = "wrong protocol ID"
	ErrWrongDestination   Error = "message is not intended for selfID"
	ErrInvalidRoundNumber Error = "round number is invalid for this protocol"
	ErrFirstRound         Error = "no message expected in first round"
	ErrLastRound          Error = "no message expected in output round"
	ErrInconsistentRound  Error = "given RoundNumber is inconsistent with content"
	ErrInvalidTo          Error = "msg.To is not valid"
	ErrInvalidContent     Error = "content is not the right type"
	ErrNilFields          Error = "message contained empty fields"
)

// Error implements error.
func (err Error) Error() string {
	return "message: " + string(err)
}
