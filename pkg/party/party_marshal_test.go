package party

import (
	"reflect"
	"testing"

	"github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

func TestPublic_MarshalJSON(t *testing.T) {
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
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
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
			got, err := p.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MarshalJSON() got = %v, want %v", got, tt.want)
			}
		})
	}
}
