package keygen

// Party is the state we store for a remote party.
// The messages are embedded to make access to the attributes easier.
type Party struct {
	message1
	message2
	message3
}

// TODO Methods for unmarshalling ProtoBufs the party
