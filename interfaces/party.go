package interfaces

const SizeID = 2

type ID uint16

func FromBytes(in []byte) ID {
	_ = in[1] // bounds check hint to compiler; see golang.org/issue/14808
	return ID(in[1]) | ID(in[0])<<8
}

func (id ID) IsBroadcast() bool {
	return id == 0
}

func (id ID) Bytes() [SizeID]byte {
	var out [SizeID]byte
	out[0] = byte(id >> 8)
	out[1] = byte(id)
	return out
}

func (id ID) BytesAppend(out []byte) []byte {
	_ = out[SizeID-1] // early bounds check to guarantee safety of writes below
	out[0] = byte(id >> 8)
	out[1] = byte(id)
	return out
}

type PartyIDs struct {
	otherPartyIDs       map[ID]bool
	otherPartyIDsSorted []ID
	allPartyIDsSorted   []ID
	selfID              ID
}

func (partyIDs *PartyIDs) Self() ID {
	return partyIDs.selfID
}

func (partyIDs *PartyIDs) IsOther(other ID) bool {
	return partyIDs.otherPartyIDs[other]
}

func (partyIDs *PartyIDs) IsParty(other ID) bool {
	return partyIDs.otherPartyIDs[other] || other == partyIDs.selfID
}

func (partyIDs *PartyIDs) SortedWithoutSelf() []ID {
	return partyIDs.otherPartyIDsSorted
}

func (partyIDs *PartyIDs) SortedWithSelf() []ID {
	return partyIDs.allPartyIDsSorted
}

func (partyIDs *PartyIDs) N() int {
	return len(partyIDs.allPartyIDsSorted)
}
