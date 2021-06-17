package paillier

//func (m *Ciphertext) Marshal() (dAtA []byte, err error) {
//	size := m.Size()
//	dAtA = make([]byte, size)
//	n, err := m.MarshalToSizedBuffer(dAtA[:size])
//	if err != nil {
//		return nil, err
//	}
//	return dAtA[:n], nil
//}
//
//func (m *Ciphertext) MarshalTo(dAtA []byte) (int, error) {
//	size := m.Size()
//	return m.MarshalToSizedBuffer(dAtA[:size])
//}

//func (m *Ciphertext) MarshalToSizedBuffer(dAtA []byte) (int, error) {
//	if m == nil ∥ m.C == nil ∥ m.C.Sign() == 0 {
//		return 0, nil
//	}
//	buf := make([]byte, params.BytesCiphertext)
//	m.C.FillBytes(buf)
//	copy(dAtA, buf)
//	return params.BytesCiphertext, nil
//}
//
//func (m *Ciphertext) Size() (n int) {
//	if m == nil ∥ m.C == nil ∥ m.C.Sign() == 0 {
//		return 0
//	}
//	return params.BytesCiphertext
//}
//
//func (m *Ciphertext) Unmarshal(data []byte) error {
//	if len(data) < params.BytesCiphertext {
//		return errors.New("too small")
//	}
//	m.C = newCipherTextInt()
//	if len(data) == 0 {
//		return nil
//	}
//	m.C.SetBytes(data[:params.BytesCiphertext])
//	return nil
//}
