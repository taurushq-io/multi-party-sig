package refresh

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
)

type Result struct {
	Session *Session
	Secret  *party.Secret
}
