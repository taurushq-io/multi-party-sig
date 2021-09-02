package round

import "github.com/taurusgroup/multi-party-sig/pkg/party"

// Abort is an empty round containing a list of parties who misbehaved.
type Abort struct {
	*Helper
	Culprits []party.ID
	Err      error
}

func (Abort) VerifyMessage(Message) error                  { return nil }
func (Abort) StoreMessage(Message) error                   { return nil }
func (r *Abort) Finalize(chan<- *Message) (Session, error) { return r, nil }
func (Abort) MessageContent() Content                      { return nil }
func (Abort) Number() Number                               { return 0 }
