package party

import "sort"

type IDSlice []ID

func (partyIDs IDSlice) Len() int           { return len(partyIDs) }
func (partyIDs IDSlice) Less(i, j int) bool { return partyIDs[i] < partyIDs[j] }
func (partyIDs IDSlice) Swap(i, j int)      { partyIDs[i], partyIDs[j] = partyIDs[j], partyIDs[i] }

// Sort is a convenience method: x.Sort() calls Sort(x).
func (partyIDs IDSlice) Sort() { sort.Sort(partyIDs) }

func (partyIDs IDSlice) Sorted() bool {
	for i := range partyIDs {
		if i > 0 && partyIDs[i-1] == partyIDs[i] {
			return false
		}
	}
	return true
}

func (partyIDs IDSlice) Contains(id ID) bool {
	idx := partyIDs.Search(id)
	return partyIDs[idx] == id
}

func (partyIDs IDSlice) GetIndex(id ID) int {
	idx := partyIDs.Search(id)
	if partyIDs[idx] == id {
		return idx
	}
	return -1
}

// Search returns the result of applying SearchStrings to the receiver and x.
func (partyIDs IDSlice) Search(x ID) int {
	return sort.Search(len(partyIDs), func(i int) bool { return partyIDs[i] >= x })
}

func (partyIDs IDSlice) Copy() IDSlice {
	a := make(IDSlice, len(partyIDs))
	copy(a, partyIDs)
	a.Sort()
	return a
}
