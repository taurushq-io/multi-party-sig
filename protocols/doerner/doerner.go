package doerner

import (
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/doerner/keygen"
	"github.com/taurusgroup/multi-party-sig/protocols/doerner/sign"
)

type (
	ConfigReceiver = keygen.ConfigReceiver
	ConfigSender   = keygen.ConfigSender
)

// EmptyConfigReceiver creates a ConfigReceiever that's ready to be unmarshalled.
//
// Because ConfigReceiver contains group dependent data, it needs to be initialized
// with a concrete group to be unmarshalled correctly.
func EmptyConfigReceiver(group curve.Curve) *ConfigReceiver {
	return &ConfigReceiver{SecretShare: group.NewScalar(), Public: group.NewPoint()}
}

// EmptyConfigSender creates a ConfigSender that's ready to be unmarshalled.
//
// Because ConfigSender contains group dependent data, it needs to be initialized
// with a concrete group to be unmarshalled correctly.
func EmptyConfigSender(group curve.Curve) *ConfigSender {
	return &ConfigSender{SecretShare: group.NewScalar(), Public: group.NewPoint()}
}

// Keygen initiates the Doerner key generation protocol.
//
// The goal of this protocol is to create a new key-pair, with the private portion
// shared between two participants.
//
// One of the participants is marked as the "Receiver", and the other is the "Sender".
// The return type of this protocol depends on the role. The Receiver will get
// a ConfigReceiver, but the Sender will get a ConfigSender instead.
//
// A pool can be passed to this function, to parallelize certain operations and improve performance.
func Keygen(group curve.Curve, receiver bool, selfID, otherID party.ID, pl *pool.Pool) protocol.StartFunc {
	return keygen.StartKeygen(group, receiver, selfID, otherID, nil, nil, pl)
}

// RefreshReceiver initiates a key-refresh protocol, from the Receiver's perspective.
//
// The goal of this protocol is to refresh the shares of the secret key, and other auxilary
// secret data, while preserving the shared public key.
//
// This won't change the value of the public key, but it will change the value of the chaining key.
// If this isn't desirable, then the new chain key can simply be overwritten with the previous value.
func RefreshReceiver(config *ConfigReceiver, selfID, otherID party.ID, pl *pool.Pool) protocol.StartFunc {
	return keygen.StartKeygen(config.Group(), true, selfID, otherID, config.SecretShare, config.Public, pl)
}

// RefreshSender initiates a key-refresh protocol, from the Sender's perspective.
//
// See RefreshReceiver.
func RefreshSender(config *ConfigSender, selfID, otherID party.ID, pl *pool.Pool) protocol.StartFunc {
	return keygen.StartKeygen(config.Group(), false, selfID, otherID, config.SecretShare, config.Public, pl)
}

// SignReceiver initiates the signing process, given a message hash.
//
// This function has another version, SignSender, which uses the config for the Sender
// instead.
//
// The result, in both cases, will be an ecdsa.Signature type.
//
// A pool can be passed to this function, to parallelize certain operations and improve performance.
func SignReceiver(config *ConfigReceiver, selfID, otherID party.ID, hash []byte, pl *pool.Pool) protocol.StartFunc {
	return sign.StartSignReceiver(config, selfID, otherID, hash, pl)
}

// SignSender is like SignReceiver, but using the Sender's results from key generation.
//
// See SignReceiver for more information.
func SignSender(config *ConfigSender, selfID, otherID party.ID, hash []byte, pl *pool.Pool) protocol.StartFunc {
	return sign.StartSignSender(config, selfID, otherID, hash, pl)
}
