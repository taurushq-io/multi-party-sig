package party

import (
	"math/rand"
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/params"
)

func TestSecret_Validate(t *testing.T) {
	rid := make([]byte, params.SecBytes)
	ssid := make([]byte, params.HashBytes)
	_, _ = rand.Read(ssid)
	_, _ = rand.Read(rid)

	x, X := sample.ScalarPointPair()

	sk := paillier.NewSecretKey()
	pk := sk.PublicKey
	ped, _ := sk.GeneratePedersen()

	id := ID("blabla")
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
		ID       ID
		ECDSA    *curve.Scalar
		Paillier *paillier.SecretKey
		RID      []byte
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
			RID:      rid,
		}, args{public}, false},
		{"pre keygen", fields{
			ID: id,
		}, args{&Public{
			ID: id,
		}}, false},

		{"no rid", fields{
			ID:       id,
			ECDSA:    x,
			Paillier: sk,
			RID:      nil,
		}, args{public}, true},
		{"short rid", fields{
			ID:       id,
			ECDSA:    x,
			Paillier: sk,
			RID:      rid[1:],
		}, args{public}, true},
		{"no paillier", fields{
			ID:       id,
			ECDSA:    x,
			Paillier: nil,
			RID:      rid,
		}, args{public}, true},
		{"no ecdsa", fields{
			ID:       id,
			ECDSA:    nil,
			Paillier: sk,
			RID:      rid,
		}, args{public}, true},
		{"no public", fields{
			ID:       id,
			ECDSA:    x,
			Paillier: sk,
			RID:      rid,
		}, args{nil}, true},

		{"no pub ped", fields{
			ID:       id,
			ECDSA:    x,
			Paillier: sk,
			RID:      rid,
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
			RID:      rid,
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
			RID:      rid,
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
				RID:      tt.fields.RID,
			}
			if err := s.ValidatePublic(tt.args.p); (err != nil) != tt.wantErr {
				t.Errorf("ValidatePublic() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
