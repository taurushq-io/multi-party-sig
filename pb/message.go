package pb

func (x *Message) IsValid() bool {
	switch x.Type {
	case MessageType_Keygen1:
		return x.GetKeygen1() != nil
	case MessageType_Keygen2:
		return x.GetKeygen2() != nil
	case MessageType_Keygen3:
		return x.GetKeygen3() != nil
	case MessageType_Refresh1:
		return x.GetRefresh1() != nil
	case MessageType_Refresh2:
		return x.GetRefresh2() != nil
	case MessageType_Refresh3:
		return x.GetRefresh3() != nil
	}
	return false
}

func (x *Message) IsBroadcast() bool {
	panic("implement me")
}

//// WriteTo implements WriterTo so that we can easily hash the message for commitment.
//func (x *KeygenMessage2) WriteTo(w io.Writer) (int64, error) {
//	var err error
//	if _, err = w.Write(x.Rid); err != nil {
//		return 0, fmt.Errorf("keygen2: write to: %w", err)
//	}
//	if _, err = w.Write(x.X.Point); err != nil {
//		return 0, fmt.Errorf("keygen2: write to: %w", err)
//	}
//	if _, err = w.Write(x.A.Point); err != nil {
//		return 0, fmt.Errorf("keygen2: write to: %w", err)
//	}
//	if _, err = w.Write(x.U); err != nil {
//		return 0, fmt.Errorf("keygen2: write to: %w", err)
//	}
//	return 0, nil
//}
//
//// WriteTo implements WriterTo so that we can easily hash the message for commitment.
//func (x *RefreshMessage2) WriteTo(w io.Writer) (int64, error) {
//	var err error
//
//	keys := make(sort.IntSlice, len(x.X), 0)
//	for k := range x.X {
//		keys = append(keys, int(k))
//	}
//	keys.Sort()
//
//	for _, k := range keys {
//		if _, err = w.Write(x.X[uint32(k)].Point); err != nil {
//			return 0, fmt.Errorf("keygen2: write to: %w", err)
//		}
//	}
//	for _, k := range keys {
//		if _, err = w.Write(x.A[uint32(k)].Point); err != nil {
//			return 0, fmt.Errorf("keygen2: write to: %w", err)
//		}
//	}
//	if _, err = w.Write(x.Y.Point); err != nil {
//		return 0, fmt.Errorf("keygen2: write to: %w", err)
//	}
//	if _, err = w.Write(x.B.Point); err != nil {
//		return 0, fmt.Errorf("keygen2: write to: %w", err)
//	}
//	if _, err = w.Write(x.N.Int); err != nil {
//		return 0, fmt.Errorf("keygen2: write to: %w", err)
//	}
//	if _, err = w.Write(x.S.Int); err != nil {
//		return 0, fmt.Errorf("keygen2: write to: %w", err)
//	}
//	if _, err = w.Write(x.T.Int); err != nil {
//		return 0, fmt.Errorf("keygen2: write to: %w", err)
//	}
//	if _, err = w.Write(x.Rho); err != nil {
//		return 0, fmt.Errorf("keygen2: write to: %w", err)
//	}
//	if _, err = w.Write(x.U); err != nil {
//		return 0, fmt.Errorf("keygen2: write to: %w", err)
//	}
//	return 0, nil
//}
