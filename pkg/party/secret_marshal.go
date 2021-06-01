package party

//var _ json.Marshaler = (*Secret)(nil)
//var _ json.Unmarshaler = (*Secret)(nil)
//
//type jsonSecret struct {
//	ID       ID                 `json:"id"`
//	ECDSA    *curve.Point             `json:"ecdsa"`
//	Paillier paillier.SecretKey `json:"paillier"`
//	RID      []byte             `json:"rid"`
//}
//
//func (s Secret) MarshalJSON() ([]byte, error) {
//	ridHex := hex.EncodeToString(s.RID)
//	ecdsaHex := hex.EncodeToString(s.ECDSA.Bytes())
//	x := jsonSecret{
//		ID:       s.ID,
//		ECDSA:    ecdsaHex,
//		Paillier: *s.Paillier,
//		RID:      ridHex,
//	}
//	return json.Marshal(x)
//}
//
//func (s *Secret) UnmarshalJSON(bytes []byte) error {
//	//var x jsonSecret
//	if err := json.Unmarshal(bytes, s); err != nil {
//		return err
//	}
//
//	//rid, err := hex.DecodeString(x.RID)
//	//if err != nil {
//	//	return err
//	//}
//	//ecdsaBytes, err := hex.DecodeString(x.ECDSA)
//	//if err != nil {
//	//	return err
//	//}
//	//ecdsa := curve.NewScalar().SetBytes(ecdsaBytes)
//	//
//	//s.ID = x.ID
//	//s.ECDSA = ecdsa
//	//s.Paillier = &x.Paillier
//	//s.RID = rid
//	return s.Validate()
//}
