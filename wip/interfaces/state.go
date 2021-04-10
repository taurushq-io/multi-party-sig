package interfaces

// State is a protocol state
type State uint32

const (
	// Init is the state if the process is just created.
	Init State = 0
	// Done is the state if the process is done.
	Done State = 10
	// Abort is the state if the process is aborting
	Abort State = 20
	// Failed is the state if the process is failed
	Failed State = 30
)

func (s State) String() string {
	switch s {
	case Init:
		return "Init"
	case Done:
		return "Done"
	case Abort:
		return "Aborting"
	case Failed:
		return "Failed"
	}
	return "Unknown"
}
