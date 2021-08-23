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

func StartKeygen(pl *pool.Pool, group curve.Curve, partyIDs []party.ID, threshold int, selfID party.ID) protocol.StartFunc {
	return keygen.StartKeygen(pl, group, partyIDs, threshold, selfID)
}

func StartRefresh(pl *pool.Pool, c *Config) protocol.StartFunc {
	return keygen.StartRefresh(pl, c)
}

func StartSign(pl *pool.Pool, config *config.Config, signers []party.ID, message []byte) protocol.StartFunc {
	return sign.StartSign(pl, config, signers, message)
}

func StartPresign(pl *pool.Pool, c *config.Config, signers []party.ID) protocol.StartFunc {
	return presign.StartPresign(pl, c, signers, nil)
}

func StartPresignOnline(c *config.Config, preSignature *ecdsa.PreSignature, message []byte) protocol.StartFunc {
	return presign.StartPresignOnline(c, preSignature, message)
}
