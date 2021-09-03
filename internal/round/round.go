package round

type Round interface {
	// VerifyMessage handles an incoming Message and validates its content with regard to the protocol specification.
	// The content argument can be cast to the appropriate type for this round without error check.
	// In the first round, this function returns nil.
	// This function should not modify any saved state as it may be be running concurrently.
	VerifyMessage(msg Message) error

	// StoreMessage should be called after VerifyMessage and should only store the appropriate fields from the
	// content.
	StoreMessage(msg Message) error

	// Finalize is called after all messages from the parties have been processed in the current round.
	// Messages for the next round are sent out through the out channel.
	// If a non-critical error occurs (like a failure to sample, hash, or send a message), the current round can be
	// returned so that the caller may try to finalize again.
	//
	// If an abort occurs, the expected behavior is to return
	//   r.AbortRound(err, culprits), nil.
	// This indicates to the caller that the protocol has aborted due to a "math" error.
	//
	// In the last round, Finalize should return
	//   r.ResultRound(result), nil
	// where result is the output of the protocol.
	Finalize(out chan<- *Message) (Session, error)

	// MessageContent returns an uninitialized message.Content for this round.
	//
	// The first round of a protocol should return nil.
	MessageContent() Content

	// Number returns the current round number.
	Number() Number
}

// BroadcastRound extends Round in that it expects a broadcast message before the p2p message.
// Due to the way Go struct inheritance works, it is necessary to implement both methods in a separate struct
// which itself only inherits the base Round. This way, we do not inherit the broadcast methods,
// and we can identify a broadcast round by type assertion.
type BroadcastRound interface {
	// StoreBroadcastMessage must be run before Round.VerifyMessage and Round.StoreMessage,
	// since those may depend on the content from the broadcast.
	// It changes the round's state to store the message after performing basic validation.
	StoreBroadcastMessage(msg Message) error

	// BroadcastContent returns an uninitialized message.Content for this round's broadcast message.
	//
	// The first round of a protocol, and rounds which do not expect a broadcast message should return nil.
	BroadcastContent() BroadcastContent

	// Round must be implemented by an inherited round which would otherwise function the same way.
	Round
}
