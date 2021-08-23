package test

import "github.com/taurusgroup/multi-party-sig/pkg/party"

// PartyIDs returns a slice of random IDs with 20 alphanumeric characters.
func PartyIDs(n int) party.IDSlice {
	ids := make(party.IDSlice, n)
	for i := range ids {
		ids[i] = party.ID('a' + rune(i))
	}
	return ids
}
