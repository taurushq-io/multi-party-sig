package pb

func (x *Message) IsValid() bool {
	if x.To == "" {

	}

	switch x.Type {
	case MessageType_TypeKeygen1:
		return x.GetKeygen1() != nil
	case MessageType_TypeKeygen2:
		return x.GetKeygen2() != nil
	case MessageType_TypeKeygen3:
		return x.GetKeygen3() != nil
	case MessageType_TypeRefresh1:
		return x.GetRefresh1() != nil
	case MessageType_TypeRefresh2:
		return x.GetRefresh2() != nil
	case MessageType_TypeRefresh3:
		return x.GetRefresh3() != nil
	}
	return false
}

//func (x *Message) IsBroadcast() bool {
//	return x.GetBroadcast()
//}
