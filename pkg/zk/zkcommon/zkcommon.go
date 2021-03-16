package zkcommon

import (
	"crypto/sha512"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

type Byteable interface {
	Bytes() []byte
}

func MakeChallenge(domain string, ssid uint32, partyID party.ID, components ...Byteable) []byte {
	h := sha512.New()

	domainBytes := make([]byte, 32)

	copy(domainBytes, domain)
	_, _ = h.Write(domainBytes)

	for _, c := range components {
		_, _ = h.Write(c.Bytes())
	}

	return h.Sum(nil)
}
