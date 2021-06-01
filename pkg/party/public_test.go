package party

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

func TestPublic_Validate(t *testing.T) {
	sk := paillier.NewSecretKey()
	p := sk.PublicKey()
	N := p.N
	ped, _ := sk.GeneratePedersen()
	ssid := make([]byte, params.HashBytes)
	_, _ = rand.Read(ssid)

	x := curve.NewScalarRandom()
	X := curve.NewIdentityPoint().ScalarBaseMult(x)
	N2 := big.NewInt(1)
	N2.Add(N2, N)
	p2 := paillier.NewPublicKey(N2)
	type fields struct {
		ID       ID
		SSID     []byte
		ECDSA    *curve.Point
		Paillier *paillier.PublicKey
		Pedersen *pedersen.Parameters
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"all ok",
			fields{
				"blabla",
				ssid,
				X,
				p,
				ped},
			false,
		},
		{"no ID",
			fields{
				"",
				ssid,
				X,
				p,
				ped},
			true,
		},
		{"no ped",
			fields{
				"",
				ssid,
				X,
				p,
				nil},
			true,
		},
		{"no paillier",
			fields{
				"",
				ssid,
				X,
				nil,
				ped},
			true,
		},
		{"missing S",
			fields{
				"",
				ssid,
				X,
				p,
				&pedersen.Parameters{
					N: N,
					S: nil,
					T: ped.T,
				}},
			true,
		},
		{"missing T",
			fields{
				"",
				ssid,
				X,
				p,
				&pedersen.Parameters{
					N: N,
					S: ped.S,
					T: nil,
				}},
			true,
		},
		{"different N",
			fields{
				"",
				ssid,
				X,
				p2,
				ped},
			true,
		},
		{"small ssid",
			fields{
				"",
				ssid[1:],
				X,
				p,
				ped},
			true,
		},
		{"no ssid",
			fields{
				"",
				nil,
				X,
				p,
				ped},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Public{
				ID:       tt.fields.ID,
				SSID:     tt.fields.SSID,
				ECDSA:    tt.fields.ECDSA,
				Paillier: tt.fields.Paillier,
				Pedersen: tt.fields.Pedersen,
			}
			if err := p.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
