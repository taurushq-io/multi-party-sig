package types

// RoundNumber is the index of the current round.
// Starts at zero
type RoundNumber uint16

// ProtocolID defines a unique identifier for a protocol.
// It will be written as {shorthand for paper}/{protocol function}-{version}-{broadcast type}
type ProtocolID string
