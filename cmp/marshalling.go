package cmp

import "encoding/json"

func (msg *msg2) MarshalJSON() ([]byte, error) {
	type Alias msg2
	GammaBin, err := msg.Gamma.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(&struct {
		Gamma []byte `json:"Gamma"`
		*Alias
	}{
		Gamma: GammaBin,
		Alias: (*Alias)(msg),
	})
}

func (msg *msg2) UnmarshalJSON(data []byte) error {
	type Alias msg2
	aux := &struct {
		Gamma []byte `json:"Gamma"`
		*Alias
	}{
		Alias: (*Alias)(msg),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	msg.Gamma = suite.Point()
	err := msg.Gamma.UnmarshalBinary(aux.Gamma)
	if err != nil {
		return err
	}
	return nil
}

func (msg *msg3) MarshalJSON() ([]byte, error) {
	type Alias msg3
	DeltaPointBin, err := msg.DeltaPoint.MarshalBinary()
	if err != nil {
		return nil, err
	}
	DeltaScalarBin, err := msg.DeltaScalar.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(&struct {
		DeltaPoint  []byte `json:"DeltaPoint"`
		DeltaScalar []byte `json:"DeltaScalar"`
		*Alias
	}{
		DeltaPoint:  DeltaPointBin,
		DeltaScalar: DeltaScalarBin,
		Alias:       (*Alias)(msg),
	})
}

func (msg *msg3) UnmarshalJSON(data []byte) error {
	type Alias msg3
	aux := &struct {
		DeltaPoint  []byte `json:"DeltaPoint"`
		DeltaScalar []byte `json:"DeltaScalar"`
		*Alias
	}{
		Alias: (*Alias)(msg),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	msg.DeltaPoint = suite.Point()
	msg.DeltaScalar = suite.Scalar()
	err := msg.DeltaPoint.UnmarshalBinary(aux.DeltaPoint)
	if err != nil {
		return err
	}
	err = msg.DeltaScalar.UnmarshalBinary(aux.DeltaScalar)
	if err != nil {
		return err
	}
	return nil
}

func (msg *msg4) MarshalJSON() ([]byte, error) {
	type Alias msg4
	SigmaBin, err := msg.Sigma.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(&struct {
		Sigma []byte `json:"Sigma"`
		*Alias
	}{
		Sigma: SigmaBin,
		Alias: (*Alias)(msg),
	})
}

func (msg *msg4) UnmarshalJSON(data []byte) error {
	type Alias msg4
	aux := &struct {
		Sigma []byte `json:"Sigma"`
		*Alias
	}{
		Alias: (*Alias)(msg),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	msg.Sigma = suite.Scalar()
	err := msg.Sigma.UnmarshalBinary(aux.Sigma)
	if err != nil {
		return err
	}
	return nil
}

func (s *Signature) MarshalJSON() ([]byte, error) {
	type Alias Signature
	RBin, err := s.R.MarshalBinary()
	SBin, err := s.S.MarshalBinary()
	MessageBin, err := s.M.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(&struct {
		R []byte `json:"R"`
		S []byte `json:"S"`
		M []byte `json:"M"`
		*Alias
	}{
		R:     RBin,
		S:     SBin,
		M:     MessageBin,
		Alias: (*Alias)(s),
	})
}

func (s *Signature) UnmarshalJSON(data []byte) error {
	type Alias Signature
	aux := &struct {
		R []byte `json:"R"`
		S []byte `json:"S"`
		M []byte `json:"M"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	s.R = suite.Point()
	s.S = suite.Scalar()
	s.M = suite.Scalar()
	err := s.R.UnmarshalBinary(aux.R)
	if err != nil {
		return err
	}
	err = s.S.UnmarshalBinary(aux.S)
	if err != nil {
		return err
	}
	err = s.M.UnmarshalBinary(aux.M)
	if err != nil {
		return err
	}
	return nil
}

func (p *Party) MarshalJSON() ([]byte, error) {
	type Alias Party
	ECDSA, err := p.ECDSA.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(&struct {
		ECDSA []byte `json:"ECDSA"`
		*Alias
	}{
		ECDSA: ECDSA,
		Alias: (*Alias)(p),
	})
}

func (p *Party) UnmarshalJSON(data []byte) error {
	type Alias Party
	aux := &struct {
		ECDSA []byte `json:"ECDSA"`
		*Alias
	}{
		Alias: (*Alias)(p),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	p.ECDSA = suite.Point()
	err := p.ECDSA.UnmarshalBinary(aux.ECDSA)
	if err != nil {
		return err
	}
	return nil
}

func (p *PartySecret) MarshalJSON() ([]byte, error) {
	type Alias PartySecret
	ECDSA, err := p.ECDSA.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(&struct {
		ECDSA []byte `json:"ECDSA"`
		*Alias
	}{
		ECDSA: ECDSA,
		Alias: (*Alias)(p),
	})
}

func (p *PartySecret) UnmarshalJSON(data []byte) error {
	type Alias PartySecret
	aux := &struct {
		ECDSA []byte `json:"ECDSA"`
		*Alias
	}{
		Alias: (*Alias)(p),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	p.ECDSA = suite.Scalar()
	err := p.ECDSA.UnmarshalBinary(aux.ECDSA)
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) MarshalJSON() ([]byte, error) {
	type Alias Config
	PK, err := c.PK.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(&struct {
		PK []byte `json:"PK"`
		*Alias
	}{
		PK:    PK,
		Alias: (*Alias)(c),
	})
}

func (c *Config) UnmarshalJSON(data []byte) error {
	type Alias Config
	aux := &struct {
		PK []byte `json:"PK"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	c.PK = suite.Point()
	err := c.PK.UnmarshalBinary(aux.PK)
	if err != nil {
		return err
	}
	return nil
}
