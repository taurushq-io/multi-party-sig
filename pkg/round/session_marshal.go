package round

import (
	"encoding/json"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

var _ json.Marshaler = (*Session)(nil)
var _ json.Unmarshaler = (*Session)(nil)

type jsonSession struct {
	// TODO include Group information
	//Group string `json:"group"`
	PublicKey *curve.Point    `json:"public_key"`
	SSID      []byte          `json:"ssid"`
	Threshold int             `json:"threshold"`
	Secret    *party.Secret   `json:"secret"`
	Public    []*party.Public `json:"public"`
}

func (s Session) MarshalJSON() ([]byte, error) {
	public := make([]*party.Public, 0, s.N())
	for _, p := range s.Public {
		public = append(public, p)
	}
	x := jsonSession{
		PublicKey: curve.NewIdentityPoint().SetPublicKey(s.PublicKey),
		SSID:      s.ssid,
		Threshold: s.Threshold,
		Secret:    s.Secret,
		Public:    public,
	}
	return json.Marshal(x)
}

func (s *Session) UnmarshalJSON(bytes []byte) error {
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

	s.group = curve.Curve
	s.PartyIDs = partyIDs
	s.Threshold = x.Threshold
	s.Public = public
	s.Secret = x.Secret
	s.PublicKey = x.PublicKey.ToPublicKey()
	s.ssid = x.SSID
	return nil
}
