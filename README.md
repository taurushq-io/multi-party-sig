# multi-party-sig

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Go implementation of multi-party threshold signing for:

- ECDSA, using the "CGGMP" protocol by [Canetti et al.](https://eprint.iacr.org/2021/060) for threshold ECDSA signing.
  We implement both the 4 round "online" and the 7 round "presigning" protocols from the paper, and adapt the
  <!-- including  with some additions to improve its practical reliability, including the "echo broadcast" from [Goldwasser and Lindell](https://doi.org/10.1007/s00145-005-0319-z).  -->

  We documented these in [docs/Threshold.pdf](docs/Threshold.pdf).
  Both the "3 round" and "7 round" protocols are implemented, and the latter supports both _identifiable aborts_ and _presigning_.
  Our implementation supports ECDSA with secp256k1.

- Schnorr signatures (as integrated in Bitcoin's Taproot), using the
  [FROST](https://eprint.iacr.org/2020/852.pdf) protocol. Because of the linear structure
  of Schnorr signatures, this protocol is less expensive thea CMP. We've also
  made the necessary adjustments to make our signatures compatible with
  Taproot's specific point encoding, as specified in [BIP-0340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).

> DISCLAIMER: Use at your own risk, this project needs further testing and auditing to be production-ready.

## Features

- **[BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) key derivation**.
  Parties can convert their shares of a public key into shares of a child key,
  as per BIP-32's key derivation spec. Only unhardened derivation is supported,
  since hardened derivation would require hashing the secret key, which no party
  has access to.
- **Constant-time arithmetic**, via [safenum](https://github.com/cronokirby/safenum).
  The CMP protocol requires Paillier encryption, as well as related ZK proofs
  performing modular arithmetic. We use a constant-time implementation of this
  arithmetic to mitigate timing-leaks
- **Parallel processing.** When possible, we parallelize heavy computation to speed
  up protocol execution.

## Usage

`multi-party-sig` was designed with the goal of supporting multiple threshold signature schemes.
Each protocol can be invoked using one of the following functions:

| Protocol Initialization                                                                                                              | Returns                                                    | Description                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| [`cmp.Keygen(group curve.Curve, selfID party.ID, participants []party.ID, threshold int, pl *pool.Pool)`](protocols/cmp/cmp.go)      | [`*cmp.Config`](protocols/cmp/config/config.go)            | Generate a new ECDSA private key shared among all the given participants.                   |
| [`cmp.Refresh(config *cmp.Config, pl *pool.Pool)`](protocols/cmp/cmp.go)                                                             | [`*cmp.Config`](protocols/cmp/config/config.go)            | Refreshes all shares of an existing ECDSA private key.                                      |
| [`cmp.Sign(config *cmp.Config, signers []party.ID, messageHash []byte, pl *pool.Pool)`](protocols/cmp/cmp.go)                        | [`*ecdsa.Signature`](pkg/ecdsa/signature.go)               | Generates an ECDSA signature for `messageHash`.                                             |
| [`cmp.Presign(config *cmp.Config, signers []party.ID, pl *pool.Pool)`](protocols/cmp/cmp.go)                                         | [`*ecdsa.PreSignature`](pkg/ecdsa/presignature.go)         | Generates a preprocessed ECDSA signature which does not depend on the message being signed. |
| [`cmp.PresignOnline(config *cmp.Config, preSignature *ecdsa.PreSignature, messageHash []byte, pl *pool.Pool)`](protocols/cmp/cmp.go) | [`*ecdsa.Signature`](pkg/ecdsa/signature.go)               | Combines each party's `PreSignature` share to create an ECDSA signature for `messageHash`.  |
| [`frost.Keygen(group curve.Curve, selfID party.ID, participants []party.ID, threshold int)`](protocols/frost/frost.go)               | [`*frost.Config`](protocols/frost/keygen/result.go)        | Generates a new Schnorr private key shared among all the given participants.                |
| [`frost.KeygenTaproot(selfID party.ID, participants []party.ID, threshold int)`](protocols/frost/frost.go)                           | [`*frost.TaprootConfig`](protocols/frost/keygen/result.go) | Generates a new Taproot compatible private key shared among all the given participants.     |
| [`frost.Sign(config *frost.Config, signers []party.ID, messageHash []byte)`](protocols/frost/frost.go)                               | [`*frost.Signature`](protocols/frost/sign/types.go)        | Generates a Schnorr signature for `messageHash`.                                            |
| [`frost.SignTaproot(config *frost.TaprootConfig, signers []party.ID, messageHash []byte)`](protocols/frost/frost.go)                 | [`*taproot.Signature`](pkg/taproot/signature.go)           | Generates a Taproot compatibe Schnorr signature for `messageHash`.                          |

In general, `Keygen` and `Refresh` protocols return a `Config` struct which contains a single key share, as well as the other participants' public key shares, and the full signing public key.
The remaining arguments should be chosen as follows:

- [`party.ID`](pkg/party/id.go) aliases a string and should uniquely identify each participant in the protocol.
- [`curve.Curve`](pkg/math/curve/curve.go) represents the cryptogrpahic group over which the protocol is defined. Currently, the only option is [`curve.Secp256k1`](pkg/math/curve/secp256k1.go).
- [`*pool.Pool`](pkg/pool/pool.go) can be used to paralelize certain operations during the protocol execution. This parameter may be nil, in which case the protocol will be run over a single thread.
  A new `pool.Pool` can be created with `pl := pool.NewPool(numberOfThreads)`, and should be freed once the protocol has finished executing by calling `pl.Teardown()`.
- `threshold` defines the maximum number of participants which may be corrupted at any given time. Generating a signature therefore requires `threshold+1` participants.
- [`*ecdsa.PreSignature`](pkg/ecdsa/presignature.go) represents a preprocessed signature share which can be generated before the message to be signed is known.
  When the message does become available, the signature can be generated in a single round.

Each of the above protocols can be executed by creating a [`protocol.Handler`](pkg/protocol/handler.go) object.
For example, we can generate a new ECDSA key as follows:

```go
var (
  // sessionID should be agreed upon beforehand, and must be unique among all protocol executions.
  // Alternatively, a counter may be used, which must be incremented after before every protocol start.
  sessionID []byte
  // group defines the cryptographic group over which
  group := curve.Secp256k1{}
  participants := []party.ID{"a", "b", "c", "d", "e"}
  selfID := participants[0] // we run the protocol as "a"
  threshold := 3 // 4 or more participants are required to generate a signature
)

pl := pool.NewPool(0) // use the maximum number of threads.
defer pl.Teardown() // destroy the pool once the protocol is done.

handler, err := protocol.NewHandler(cmp.Keygen(group, selfID, participants, threshold, pl), sessionID)
if err != nil {
  // the handler was not able to start the protocol, most likely due to incorrect configuration.
}
```

More examples of how to create handlers for various protocols can be found in [/example](/example).

After the handler has been created, the user can start a loop for incoming/outgoing messages.
Messages for other parties can be obtained by querying the channel returned by `handler.Listen()`.
If the channel is closed, then the user can assume the protocol has finished.

```go
func runProtocol(handler *protocol.Handler) {
  // Message handling loop
  for {
    select {

    // Message to be sent to other participants
    case msgOut, ok := <-handler.Listen():
      // a closed channel indicates that the protocol has finished executing
      if !ok {
        return
      }
      if msgOut.Broadcast {
        // ensure this message is reliably broadcast	
      }
      for _, id := range participants {
        if msgOut.IsFor(id) {
          // send the message to `id`
        }   
      }

    // Incoming message
    case msgIn := <- Receive():
      if !handler.CanAccept(msg) {
        // basic header validation failed, the message may be intended for a different protocol execution.
        continue
      }
      handler.Update(msgIn)
    }
  }
}

// runProtocol blocks until the protocol succeeds or aborts
runProtocol(handler)

// obtain the final result, or a possible error
result, err := handler.Result()
protocolError := protocol.Error{}
if errors.As(err, protocolError) {
  // get the list of culprits by calling protocolError.Culprits
}
// if the error is nil, then we can cast the result to the expected return type
config := result.(*cmp.Config)
```

If an error has occurred, it will be returned as a [`protocol.Error`](pkg/protocol/error.go), 
which may contain information on the responsible participants, if possible.

When the protocol successfully completes, the result must be cast to the appropriate type.

### Network

Most messages returned by the protocol can be transmitted through a point-to-point network guaranteeing authentication, integrity and confidentiality.
The user is responsible for delivering the message to all participants for which `Message.IsFor(recipient)` returns `true`.

Some messages however require a _reliable_ broadcast channel, which guarantees that all participants agree on which messages were sent.
These messages will have their `Message.Broadcast` field set to `true`.
The `protocol.Handler` performs an additional check due to [Goldwasser & Lindell](https://eprint.iacr.org/2002/040),
which ensures that the protocol aborts when some participants incorrectly broadcast these types of messages.
Unfortunately, identifying the culprits in this case requires external assumption which cannot be handled by this library.

[comment]: <> (### Keygen)

[comment]: <> (The [`protocols/keygen`]&#40;protocols/cmp/keygen&#41; package can be used to perform a distributed key generation.)

[comment]: <> (A [`protocol.Handler`]&#40;pkg/protocol/handler.go&#41; is created by specifying the list of `partyIDs` who will receive a share,)

[comment]: <> (and the `selfID` corresponding to this party's ID.)

[comment]: <> (The `threshold` defines the maximum number of corrupt parties tolerated.)

[comment]: <> (That is, the secret key may only be reconstructed using any `threshold+1` different key shares.)

[comment]: <> (This is therefore also the minimum number of participants required to create a signature.)

[comment]: <> (```go)

[comment]: <> (partyIDs := []party.ID{"a", "b", "c", "d", "e"})

[comment]: <> (selfID := party.ID&#40;"a"&#41;)

[comment]: <> (threshold := 3)

[comment]: <> (keygenHandler, err := protocol.NewHandler&#40;keygen.StartKeygen&#40;partyIDs, threshold, selfID&#41;&#41;)

[comment]: <> (result, err := runProtocolHandler&#40;keygenHandler&#41;)

[comment]: <> (if err != nil {)

[comment]: <> (    // investigate error)

[comment]: <> (})

[comment]: <> (config := r.&#40;*keygen.Config&#41;)

[comment]: <> (```)

[comment]: <> (The [`config`]&#40;/protocols/cmp/keygen/config.proto&#41; object contains all necessary data to create a signature.)

[comment]: <> (`Config.PublicKey&#40;&#41;` returns an `ecdsa.PublicKey` for which the parties can generate signatures.)

[comment]: <> (### Refresh)

[comment]: <> (Participant's shares of the ECDSA private key can be refreshed after the initial key generation was successfully performed.)

[comment]: <> (It requires all share holders to be present, and the result is a new [`keygen.Config`]&#40;/protocols/cmp/keygen/config.go&#41;.)

[comment]: <> (The original ECDSA public key remains the same, but the secret is refreshed.)

[comment]: <> (```go)

[comment]: <> (refreshHandler, err := protocol.NewHandler&#40;keygen.StartRefresh&#40;config&#41;&#41;)

[comment]: <> (result, err := runProtocolHandler&#40;keygenHandler&#41;)

[comment]: <> (if err != nil {)

[comment]: <> (    // investigate error)

[comment]: <> (})

[comment]: <> (refreshedConfig := r.&#40;*keygen.Config&#41;)

[comment]: <> (```)

[comment]: <> (### Sign)

[comment]: <> (The [`sign`]&#40;/protocols/cmp/sign&#41; protocol implements the "3 Round" signing protocol from CGGMP21, without pre-signing or identifiable aborts.)

[comment]: <> (Both these features may be implemented in a future version of `multi-party-sig`.)

[comment]: <> (The resulting signature is a valid ECDSA key.)

[comment]: <> (```go)

[comment]: <> (message := []byte&#40;"hello, world"&#41;)

[comment]: <> (// since threshold is 3, we need for or more parties to)

[comment]: <> (signers := []party.ID{"a", "b", "c", "d"})

[comment]: <> (signHandler, err := protocol.NewHandler&#40;sign.StartSign&#40;refreshedConfig, signers, message&#41;&#41;)

[comment]: <> (result, err := runProtocolHandler&#40;signHandler&#41;)

[comment]: <> (if err != nil {)

[comment]: <> (    // investigate error)

[comment]: <> (})

[comment]: <> (signature := r.&#40;*ecdsa.Signature&#41;)

[comment]: <> (signature.Verify&#40;refreshedConfig.PublicPoint&#40;&#41;, message&#41;)

[comment]: <> (```)

## Intellectual property

This code is copyright (c) Adrian Hamelink and Taurus SA, 2021, and under Apache 2.0 license.

On potential patents: the company that sponsored the development of the CMP
protocol [stated](https://apnews.com/press-release/pr-newswire/26aab91e254bc254d331ceafc20b9859)
that it "will not be applying for patents on this technology."
