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

func (x *ZKEnc) IsValid() bool {
	if x == nil {
		return false
	}

	if x.GetA() == nil ||
		x.GetZ3() == nil {
		return false
	}

	return true
}

func (x *ZKAffG) IsValid() bool {
	if x == nil {
		return false
	}
	if x.GetA() == nil ||
		x.GetBy() == nil ||
		x.GetW() == nil ||
		x.GetWy() == nil {
		return false
	}
	return true
}
