package rounds

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/messages"
)

type Round interface {
	// A Round represents the state of protocol from the perspective of the party.
	//
	//

	// StoreMessage accepts any unmarshalled message and attempts to store it for later use in the round
	// It check whether the message is for the right protocol, and whether relevant fields are not nil.
	StoreMessage(message *messages.Message) error

	// ProcessMessages only runs when all messages for the current round have been received.
	// It performs any checks and validation necessary, and updates the round's state.
	ProcessMessages()

	// ProcessRound performs all steps necessary to compute outgoing messages.
	// The state is updated, and any subsequent calls will result in an error.
	ProcessRound()

	// GenerateMessages returns a slice of messages to be sent out at the end of this round.
	// If it is not possible for some reason, an empty slice is returned.
	GenerateMessages() []*messages.Message

	// NextRound will return the next round that is possible at the time.
	// If it is not possible to advance to the next round, then the current one is returned.
	NextRound() Round

	Info
}

type Info interface {
	// ID of the signer.
	ID() uint32

	// RoundNumber indicates which run the protocol is in.
	RoundNumber() int

	// WaitForFinish blocks until the protocol has succeeded, or an error has occurred.
	// If so the error is returned.
	// In both cases, the
	WaitForFinish() error
}

//type KeyGenRound interface {
//	Round
//	WaitForKeygenOutput() (groupKey *eddsa.PublicKey, groupKeyShares eddsa.PublicKeyShares, secretKeyShare *eddsa.PrivateKey, err error)
//}
//
//type SignRound interface {
//	Round
//	WaitForSignOutput() (signature *eddsa.Signature, err error)
//}
