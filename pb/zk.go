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
		x.GetWy() == nil ||
		x.GetZ1() == nil ||
		x.GetZ2() == nil ||
		x.GetZ3() == nil {
		return false
	}
	return true
}

func (x *ZKLogStar) IsValid() bool {
	if x == nil {
		return false
	}
	if x.GetS() == nil ||
		x.GetA() == nil ||
		x.GetY() == nil ||
		x.GetD() == nil ||
		x.GetZ1() == nil ||
		x.GetZ2() == nil ||
		x.GetZ3() == nil {
		return false
	}
	return true
}
