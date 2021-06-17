package round

type Round interface {
	// ProcessMessage handles an incoming Message.
	// In general, it should not modify the underlying Round, but only the sender's local state.
	// At the end, the message is stored
	ProcessMessage(msg Message) error

	// GenerateMessages returns an array of Message to be sent subsequently.
	// If an error has been detected, then no messages are returned.
	GenerateMessages() ([]Message, error)

	// Finalize performs
	Finalize() (Round, error)

	// MessageType returns the expected MessageType for the current round.
	MessageType() MessageType
}
