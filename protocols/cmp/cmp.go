package cmp

import (
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/config"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/keygen"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/presign"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/sign"
)

type Config = config.Config

func StartKeygen(group curve.Curve, partyIDs []party.ID, threshold int, selfID party.ID, pl *pool.Pool) protocol.StartFunc {
	return keygen.StartKeygen(group, partyIDs, threshold, selfID, pl)
}

func StartRefresh(c *Config, pl *pool.Pool) protocol.StartFunc {
	return keygen.StartRefresh(c, pl)
}

func StartSign(config *config.Config, signers []party.ID, message []byte, pl *pool.Pool) protocol.StartFunc {
	return sign.StartSign(config, signers, message, pl)
}

func StartPresign(c *config.Config, signers []party.ID, pl *pool.Pool) protocol.StartFunc {
	return presign.StartPresign(c, signers, nil, pl)
}

func StartPresignOnline(c *config.Config, preSignature *ecdsa.PreSignature, message []byte, pl *pool.Pool) protocol.StartFunc {
	return presign.StartPresignOnline(c, preSignature, message, pl)
}
