//go:generate protoc -I=. -I=proto -I=$GOPATH/src -I=$GOPATH/src/github.com/gogo/protobuf/protobuf  --gogoslick_out=. message.proto
package pb

import "github.com/taurusgroup/cmp-ecdsa/pkg/party"

func (x *Message) GetFromID() party.ID {
	return party.ID(x.From)
}

func (x *Message) GetToID() party.ID {
	return party.ID(x.To)
}

func (x *Message) IsValid() bool {
	switch x.Type {
	// refresh_old
	case MessageTypeRefresh1:
		return x.GetRefresh1() != nil
	case MessageTypeRefresh2:
		return x.GetRefresh2() != nil
	case MessageTypeRefresh3:
		return x.GetRefresh3() != nil
	case MessageTypeRefresh4:
		return x.GetRefresh4() != nil
	// sign
	case MessageTypeSign1:
		return x.GetSign1() != nil
	case MessageTypeSign2:
		return x.GetSign2() != nil
	case MessageTypeSign3:
		return x.GetSign3() != nil
	case MessageTypeSign4:
		return x.GetSign4() != nil
	// sign abort
	case MessageTypeAbort1:
		return x.GetAbort1() != nil
	case MessageTypeAbort2:
		return x.GetAbort2() != nil
	}
	return false
}
