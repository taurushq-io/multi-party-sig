package refresh

import (
	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/session"
)

type Result struct {
	Session *session.Session
	Secret  *party.Secret
}
