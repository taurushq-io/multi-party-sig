package curve

import (
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
			args{n: q},
			&Scalar{s: secp256k1.ModNScalar{}},
		},
		{
			"q+1",
			args{n: new(big.Int).Add(q, big.NewInt(1))},
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
				x: NewScalarBigInt(q),
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
