package pb

import "github.com/taurusgroup/cmp-ecdsa/pkg/params"

func (x *ZKMod) IsValid() bool {
	if x == nil {
		return false
	}
	if len(x.X) != params.StatParam ||
		len(x.A) != params.StatParam ||
		len(x.B) != params.StatParam ||
		len(x.Z) != params.StatParam {
		return false
	}
	if !x.W.IsValid() || x.W.Zero {
		return false
	}
	return true
}

func (x *ZKPrm) IsValid() bool {
	if x == nil {
		return false
	}
	if len(x.A) != params.StatParam ||
		len(x.Z) != params.StatParam {
		return false
	}
	return true
}
