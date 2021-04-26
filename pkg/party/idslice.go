package party

type IDSlice []uint32

func (partyIDs IDSlice) Len() int {
	return len(partyIDs)
}

func (partyIDs IDSlice) Less(i, j int) bool {
	return partyIDs[i] < partyIDs[j]
}

func (partyIDs IDSlice) Swap(i, j int) {
	partyIDs[i], partyIDs[j] = partyIDs[j], partyIDs[i]
}

func (partyIDs IDSlice) Contains(id uint32) bool {
	// Define f(-1) == false and f(n) == true.
	// Invariant: f(i-1) == false, f(j) == true.
	i, j := 0, len(partyIDs)
	for i < j {
		h := int(uint(i+j) >> 1) // avoid overflow when computing h
		// i ≤ h < j
		if partyIDs[h] < id {
			i = h + 1 // preserves f(i-1) == false
		} else {
			j = h // preserves f(j) == true
		}
	}
	// i == j, f(i-1) == false, and f(j) (= f(i)) == true  =>  answer is i.
	return id == partyIDs[i]
}
func (partyIDs IDSlice) GetIndex(id uint32) int {
	i, j := 0, len(partyIDs)
	for i < j {
		h := int(uint(i+j) >> 1) // avoid overflow when computing h
		// i ≤ h < j
		if partyIDs[h] < id {
			i = h + 1 // preserves f(i-1) == false
		} else {
			j = h // preserves f(j) == true
		}
	}
	// i == j, f(i-1) == false, and f(j) (= f(i)) == true  =>  answer is i.
	if id == partyIDs[i] {
		return i
	} else {
		return -1
	}
}
