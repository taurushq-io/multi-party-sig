package round

import (
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol/message"
)

type Round interface {
	// VerifyMessage handles an incoming Message from j and validates it's content with regard to the protocol specification.
	// The content argument can be cast to the appropriate type for this round without error check.
	// In the first round, this function returns nil.
	// This function should not modify any saved state as it may be be running concurrently.
	VerifyMessage(from party.ID, to party.ID, content message.Content) error

	// StoreMessage should be called after VerifyMessage and should only store the appropriate fields from the
	// content.
	StoreMessage(from party.ID, content message.Content) error

	// Finalize is called after all messages from the parties have been processed in the current round.
	// Messages for the next round are sent out through the out channel.
	// If a non-critical error occurs (like a failure to sample, hash, or send a message), the current round can be
	// returned so that the caller may try to finalize again.
	// When the protocol is aborted, a nil round should be returned.
	//
	// In the last round, Finalize should return
	//   &round.Final{result}, nil
	// where result is the output of the protocol.
	Finalize(out chan<- *message.Message) (Round, error)

	// MessageContent returns an uninitialized message.Content for this round.
	// It can be used to get the current round number by calling MessageContent().RoundNumber().
	//
	// The first round of a protocol should return &message.First{}.
	MessageContent() message.Content
}
