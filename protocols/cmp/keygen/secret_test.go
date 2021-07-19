package keygen

import (
	"crypto/rand"
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

func TestSecret_Validate(t *testing.T) {
	rid := make([]byte, params.SecBytes)
	ssid := make([]byte, params.HashBytes)
	_, _ = rand.Read(ssid)
	_, _ = rand.Read(rid)

	x, X := sample.ScalarPointPair(rand.Reader)

	sk := paillier.NewSecretKey()
	pk := sk.PublicKey
	ped, _ := sk.GeneratePedersen()

	id := party.ID("blabla")
	public := &Public{
		ID:       id,
		ECDSA:    X,
		Paillier: pk,
		Pedersen: ped,
	}

	//N2 := big.NewInt(1)
	//N2.Add(N2, N)
	//pk2 := paillier.NewPublicKey(N2)

	type fields struct {
		ID       party.ID
		ECDSA    *curve.Scalar
		Paillier *paillier.SecretKey
	}
	type args struct {
		p *Public
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// passing
		{"all ok", fields{
			ID:       id,
			ECDSA:    x,
			Paillier: sk,
		}, args{public}, false},
		{"pre keygen", fields{
			ID: id,
		}, args{&Public{
			ID: id,
		}}, false},
		{"no paillier", fields{
			ID:       id,
			ECDSA:    x,
			Paillier: nil,
		}, args{public}, true},
		{"no ecdsa", fields{
			ID:       id,
			ECDSA:    nil,
			Paillier: sk,
		}, args{public}, true},
		{"no public", fields{
			ID:       id,
			ECDSA:    x,
			Paillier: sk,
		}, args{nil}, true},

		{"no pub ped", fields{
			ID:       id,
			ECDSA:    x,
			Paillier: sk,
		}, args{&Public{
			ID:       id,
			ECDSA:    X,
			Paillier: pk,
			Pedersen: nil,
		}}, true},
		{"no pub paillier", fields{
			ID:       id,
			ECDSA:    x,
			Paillier: sk,
		}, args{&Public{
			ID:       id,
			ECDSA:    X,
			Paillier: nil,
			Pedersen: ped,
		}}, true},
		{"no pub ecdsa", fields{
			ID:       id,
			ECDSA:    x,
			Paillier: sk,
		}, args{&Public{
			ID:       id,
			ECDSA:    nil,
			Paillier: pk,
			Pedersen: ped,
		}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Secret{
				ID:       tt.fields.ID,
				ECDSA:    tt.fields.ECDSA,
				Paillier: tt.fields.Paillier,
			}
			if err := s.ValidatePublic(tt.args.p); (err != nil) != tt.wantErr {
				t.Errorf("ValidatePublic() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
