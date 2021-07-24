package keygen

//
//import (
//	"crypto/rand"
//	"math/big"
//	"testing"
//
//	"github.com/stretchr/testify/assert"
//	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
//	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
//	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
//	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
//	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
//)
//
//func TestSecret_Validate(t *testing.T) {
//	x, X := sample.ScalarPointPair(rand.Reader)
//
//	sk := paillier.NewSecretKey()
//	pk := sk.PublicKey
//	ped, _ := sk.GeneratePedersen()
//
//	id := party.ID("blabla")
//	public := &Public{
//		ECDSA:    X,
//		Paillier: pk,
//		Pedersen: ped,
//	}
//
//	//N2 := big.NewInt(1)
//	//N2.Add(N2, N)
//	//pk2 := paillier.NewPublicKey(N2)
//
//	type fields struct {
//		ID       party.ID
//		ECDSA    *curve.Scalar
//		Paillier *paillier.SecretKey
//	}
//	type args struct {
//		p *Public
//	}
//	tests := []struct {
//		name    string
//		fields  fields
//		args    args
//		wantErr bool
//	}{
//		// passing
//		{"all ok", fields{
//			ID:       id,
//			ECDSA:    x,
//			Paillier: sk,
//		}, args{public}, false},
//		{"pre keygen", fields{
//			ID: id,
//		}, args{&Public{}}, true},
//		{"no paillier", fields{
//			ID:       id,
//			ECDSA:    x,
//			Paillier: nil,
//		}, args{public}, true},
//		{"no ecdsa", fields{
//			ID:       id,
//			ECDSA:    nil,
//			Paillier: sk,
//		}, args{public}, true},
//		{"no public", fields{
//			ID:       id,
//			ECDSA:    x,
//			Paillier: sk,
//		}, args{nil}, true},
//
//		{"no pub ped", fields{
//			ID:       id,
//			ECDSA:    x,
//			Paillier: sk,
//		}, args{&Public{
//			ECDSA:    X,
//			Paillier: pk,
//			Pedersen: nil,
//		}}, true},
//		{"no pub paillier", fields{
//			ID:       id,
//			ECDSA:    x,
//			Paillier: sk,
//		}, args{&Public{
//			ECDSA:    X,
//			Paillier: nil,
//			Pedersen: ped,
//		}}, true},
//		{"no pub ecdsa", fields{
//			ECDSA:    x,
//			Paillier: sk,
//		}, args{&Public{
//			ECDSA:    nil,
//			Paillier: pk,
//			Pedersen: ped,
//		}}, true},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			s := &Secret{
//				ID:       tt.fields.ID,
//				ECDSA:    tt.fields.ECDSA,
//				Paillier: tt.fields.Paillier,
//			}
//			if err := s.ValidatePublic(tt.args.p); (err != nil) != tt.wantErr {
//				t.Errorf("ValidatePublic() error = %v, wantErr %v", err, tt.wantErr)
//			}
//		})
//	}
//}
//
//func TestPublic_Validate(t *testing.T) {
//	sk := paillier.NewSecretKey()
//	p := sk.PublicKey
//	N := p.N()
//	ped, _ := sk.GeneratePedersen()
//
//	_, X := sample.ScalarPointPair(rand.Reader)
//	N2 := big.NewInt(1)
//	N2.Add(N2, N)
//	p2, _ := paillier.NewPublicKey(N2)
//	type fields struct {
//		ECDSA    *curve.Point
//		Paillier *paillier.PublicKey
//		Pedersen *pedersen.Parameters
//	}
//	tests := []struct {
//		name    string
//		fields  fields
//		wantErr bool
//	}{
//		{"all ok",
//			fields{
//				X,
//				p,
//				ped},
//			false,
//		},
//		{"no ped",
//			fields{
//				X,
//				p,
//				nil},
//			true,
//		},
//		{"no paillier",
//			fields{
//				X,
//				nil,
//				ped},
//			true,
//		},
//		{"different N",
//			fields{
//				X,
//				p2,
//				ped},
//			true,
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			p := &Public{
//				ECDSA:    tt.fields.ECDSA,
//				Paillier: tt.fields.Paillier,
//				Pedersen: tt.fields.Pedersen,
//			}
//			if err := p.Validate(); (err != nil) != tt.wantErr {
//				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
//			}
//		})
//	}
//}
