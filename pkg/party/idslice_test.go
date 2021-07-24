package party

import "testing"

func TestIDSlice_GetIndex(t *testing.T) {
	tests := []struct {
		name     string
		partyIDs IDSlice
		requestedID ID
		want     int
	}{
		{"empty", IDSlice{}, "a", -1},
	},
		for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.partyIDs.GetIndex(tt.requestedID); got != tt.want {
				t.Errorf("GetIndex() = %v, want %v", got, tt.want)
			}
		})
	}
}
