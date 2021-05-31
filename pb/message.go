package pb

import "github.com/taurusgroup/cmp-ecdsa/pkg/party"

func (x *Message) GetFromID() party.ID {
	return party.ID(x.From)
}

func (x *Message) GetToID() party.ID {
	return party.ID(x.To)
}

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
	case MessageType_TypeSign1:
		return x.GetSign1() != nil
	case MessageType_TypeSign2:
		return x.GetSign2() != nil
	case MessageType_TypeSign3:
		return x.GetSign3() != nil
	case MessageType_TypeSign4:
		return x.GetSign4() != nil
	case MessageType_TypeAbort1:
		return x.GetAbort1() != nil
	case MessageType_TypeAbort2:
		return x.GetAbort2() != nil
	}
	return false
}

//func (x *Message) IsBroadcast() bool {
//	return x.GetBroadcast()
//}
