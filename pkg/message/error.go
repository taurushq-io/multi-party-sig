package message

// Error indicates that the message does not pass validation
type Error string

const (
	ErrMessageDuplicate          Error = "message: message was already handled"
	ErrMessageUnknownSender      Error = "message: unknown sender"
	ErrMessageNilContent         Error = "message: message content is nil"
	ErrMessageWrongSSID          Error = "message: SSID mismatch"
	ErrMessageWrongProtocolID    Error = "message: wrong protocol ID"
	ErrMessageFromSelf           Error = "message: message is from Self"
	ErrMessageNotSorted          Error = "message: msg.To field is not sorted"
	ErrMessageContainsDuplicates Error = "message: msg.To field contains duplicates"
	ErrMessageWrongDestination   Error = "message: message is not intended for selfID"
	ErrMessageInvalidRoundNumber Error = "message: round number is invalid for this protocol"
)

// Error implements error
func (err Error) Error() string {
	return string(err)
}
