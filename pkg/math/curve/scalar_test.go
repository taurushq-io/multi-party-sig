package curve

import (
	"bytes"
	"math/big"
	"reflect"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"github.com/stretchr/testify/assert"
)

func TestNewScalar(t *testing.T) {
	var s2 Scalar
	s1 := *NewScalar()
	assert.EqualValues(t, s1, s2)
}

func TestNewScalarBigInt(t *testing.T) {
	type args struct {
		n *big.Int
	}
	tests := []struct {
		name string
		args args
		want *Scalar
	}{
		{
			"0",
			args{n: big.NewInt(0)},
			&Scalar{s: *(&secp256k1.ModNScalar{}).SetInt(0)},
		},
		{
			"1",
			args{n: big.NewInt(1)},
			&Scalar{s: *(&secp256k1.ModNScalar{}).SetInt(1)},
		},
		{
			"q",
			args{n: Q},
			&Scalar{s: secp256k1.ModNScalar{}},
		},
		{
			"q+1",
			args{n: new(big.Int).Add(Q, big.NewInt(1))},
			&Scalar{s: *(&secp256k1.ModNScalar{}).SetInt(1)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewScalarBigInt(tt.args.n); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewScalarBigInt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScalar_Add(t *testing.T) {
	type fields struct {
		s secp256k1.ModNScalar
	}
	type args struct {
		x *Scalar
		y *Scalar
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Scalar
	}{
		{
			"0+0",
			fields{s: secp256k1.ModNScalar{}},
			args{
				x: NewScalar().SetUInt32(0),
				y: NewScalar().SetUInt32(0),
			},
			NewScalar().SetUInt32(0),
		},
		{
			"1+1",
			fields{s: secp256k1.ModNScalar{}},
			args{
				x: NewScalar().SetUInt32(1),
				y: NewScalar().SetUInt32(1),
			},
			NewScalar().SetUInt32(2),
		},
		{
			"q+1",
			fields{s: secp256k1.ModNScalar{}},
			args{
				x: NewScalarBigInt(Q),
				y: NewScalar().SetUInt32(1),
			},
			NewScalar().SetUInt32(1),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scalar{
				s: tt.fields.s,
			}
			if got := s.Add(tt.args.x, tt.args.y); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Add() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScalar_BigInt(t *testing.T) {
	type fields struct {
		s secp256k1.ModNScalar
	}
	tests := []struct {
		name   string
		fields fields
		want   *big.Int
	}{
		{
			"0",
			fields{s: secp256k1.ModNScalar{}},
			big.NewInt(0),
		},
		{
			"1",
			fields{s: *(&secp256k1.ModNScalar{}).SetInt(1)},
			big.NewInt(1),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scalar{
				s: tt.fields.s,
			}
			if got := s.BigInt(); got.Cmp(tt.want) != 0 {
				t.Errorf("BigInt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScalar_Equal(t *testing.T) {
	type fields struct {
		s secp256k1.ModNScalar
	}
	type args struct {
		t *Scalar
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scalar{
				s: tt.fields.s,
			}
			if got := s.Equal(tt.args.t); got != tt.want {
				t.Errorf("Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScalar_Invert(t *testing.T) {
	type fields struct {
		s secp256k1.ModNScalar
	}
	type args struct {
		t *Scalar
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Scalar
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scalar{
				s: tt.fields.s,
			}
			if got := s.Invert(tt.args.t); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Invert() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScalar_IsZero(t *testing.T) {
	type fields struct {
		s secp256k1.ModNScalar
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scalar{
				s: tt.fields.s,
			}
			if got := s.IsZero(); got != tt.want {
				t.Errorf("IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScalar_Multiply(t *testing.T) {
	type fields struct {
		s secp256k1.ModNScalar
	}
	type args struct {
		x *Scalar
		y *Scalar
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Scalar
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scalar{
				s: tt.fields.s,
			}
			if got := s.Multiply(tt.args.x, tt.args.y); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Multiply() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScalar_MultiplyAdd(t *testing.T) {
	type fields struct {
		s secp256k1.ModNScalar
	}
	type args struct {
		x *Scalar
		y *Scalar
		z *Scalar
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Scalar
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scalar{
				s: tt.fields.s,
			}
			if got := s.MultiplyAdd(tt.args.x, tt.args.y, tt.args.z); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MultiplyAdd() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScalar_Negate(t *testing.T) {
	type fields struct {
		s secp256k1.ModNScalar
	}
	type args struct {
		x *Scalar
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Scalar
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scalar{
				s: tt.fields.s,
			}
			if got := s.Negate(tt.args.x); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Negate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScalar_Set(t *testing.T) {
	type fields struct {
		s secp256k1.ModNScalar
	}
	type args struct {
		x *Scalar
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Scalar
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scalar{
				s: tt.fields.s,
			}
			if got := s.Set(tt.args.x); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Set() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScalar_SetBigInt(t *testing.T) {
	type fields struct {
		s secp256k1.ModNScalar
	}
	type args struct {
		i *big.Int
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Scalar
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scalar{
				s: tt.fields.s,
			}
			if got := s.SetBigInt(tt.args.i); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetBigInt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScalar_SetBytes(t *testing.T) {
	type fields struct {
		s secp256k1.ModNScalar
	}
	type args struct {
		in []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Scalar
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scalar{
				s: tt.fields.s,
			}
			if got := s.SetBytes(tt.args.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScalar_SetHash(t *testing.T) {
	type fields struct {
		s secp256k1.ModNScalar
	}
	type args struct {
		hash []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Scalar
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scalar{
				s: tt.fields.s,
			}
			if got := s.SetHash(tt.args.hash); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScalar_SetUInt32(t *testing.T) {
	type fields struct {
		s secp256k1.ModNScalar
	}
	type args struct {
		i uint32
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Scalar
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scalar{
				s: tt.fields.s,
			}
			if got := s.SetUInt32(tt.args.i); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetUInt32() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScalar_Subtract(t *testing.T) {
	type fields struct {
		s secp256k1.ModNScalar
	}
	type args struct {
		x *Scalar
		y *Scalar
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Scalar
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scalar{
				s: tt.fields.s,
			}
			if got := s.Subtract(tt.args.x, tt.args.y); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Subtract() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScalar_WriteTo(t *testing.T) {
	type fields struct {
		s secp256k1.ModNScalar
	}
	tests := []struct {
		name    string
		fields  fields
		wantW   string
		want    int64
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Scalar{
				s: tt.fields.s,
			}
			w := &bytes.Buffer{}
			got, err := s.WriteTo(w)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteTo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("WriteTo() gotW = %v, want %v", gotW, tt.wantW)
			}
			if got != tt.want {
				t.Errorf("WriteTo() got = %v, want %v", got, tt.want)
			}
		})
	}
}
