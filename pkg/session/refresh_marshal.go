package session

import (
	"encoding/json"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

var _ json.Marshaler = (*KeygenSession)(nil)
var _ json.Unmarshaler = (*KeygenSession)(nil)

type jsonSession struct {
	// TODO include Group information
	//Group string `json:"group"`
	PublicKey *curve.Point    `json:"public_key"`
	SSID      []byte          `json:"ssid"`
	Threshold int             `json:"threshold"`
	Secret    *party.Secret   `json:"secret"`
	Public    []*party.Public `json:"public"`
}

func (s KeygenSession) MarshalJSON() ([]byte, error) {
	public := make([]*party.Public, 0, s.N())
	for _, id := range s.PartyIDs() {
		public = append(public, s.Public(id))
	}
	x := jsonSession{
		PublicKey: curve.FromPublicKey(s.PublicKey()),
		SSID:      s.SSID(),
		Threshold: s.Threshold(),
		Secret:    s.Secret(),
		Public:    public,
	}
	return json.Marshal(x)
}

func (s *KeygenSession) UnmarshalJSON(bytes []byte) error {
	var x jsonSession
	err := json.Unmarshal(bytes, &x)
	if err != nil {
		return err
	}

	n := len(x.Public)
	public := make(map[party.ID]*party.Public, n)
	partyIDs := make(party.IDSlice, 0, n)
	for _, partyJ := range x.Public {
		partyIDs = append(partyIDs, partyJ.ID)
		public[partyJ.ID] = partyJ
	}
	partyIDs.Sort()

	s2, err := NewSession(x.Threshold, public, x.PublicKey.ToPublicKey(), x.Secret, x.SSID)
	if err != nil {
		return err
	}
	*s = *s2
	return nil
}
