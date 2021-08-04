# multi-party-sig

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Go implementation of multi-party threshold signing for: 

* ECDSA, using the "CMP" protocol by [Canetti et al.](https://eprint.iacr.org/2021/060) for threshold ECDSA signing, with some additions to improve its practical reliability, including the "echo broadcast" from [Goldwasser and Lindell](https://doi.org/10.1007/s00145-005-0319-z). We documented these in [threshold_protocol.pdf](threshold_protocol.pdf). A list of proposed improvements is in [TODO.md](TODO.md). Our implementation supports ECDSA with secp256k1.

* Schnorr signatures (as integrated in Bitcoin's Taproot), using the FROST protocol. (Elaborate...)

## Features

TODO (BIP32, safenum, etc.)

## Usage

`multi-party-sig` was designed with the goal of supporting multiple threshold signature schemes.
Protocols such as [`keygen`](protocols/cmp/keygen) or [`sign`](protocols/cmp/sign) are defined in the [protocols](/protocols) directory.
These packages define:

- one or more `Start...(...)` functions for initializing a protocol.
- a `Result` struct containing the output.

### Protocol Handler

A [`protocol.Handler`](pkg/protocol/handler.go) takes care of validating and processing messages.
It is created by calling `protocol.NewHandler` with the `Start...(...)` function as argument:

```go
handler, err := protocol.NewHandler(Start...(arguments...))
```

The following code snippet is a simplified description of what a standard protocol execution would look like,
and a full example is given in [/example](/example).

After the handler has been created, the user can start a loop for incoming/outgoing messages.
Messages for other parties can be obtained by querying the channel returned by `handler.Listen()`.
If the channel is closed, then the user can assume the protocol has finished.

```go
func runProtocolHandler(handler *protocol.Handler) (interface{}, error) {
    // Message handling loop
    for {
        select {
        // Message to be sent to other parties
        case msgOut, ok := <-handler.Listen():
            // a closed channel indicates that the protocol has finished executing
            if !ok {
                return
            }
            Send(msgOut)
        // Incoming message
        case msgIn := <- Receive():
            err := handler.Update(msgIn)
            messageError := new(message.Error)
            if errors.As(err, &messageError) {
                // the message failed validation and was not processed
            }
        }
    }

    // The protocol has stopped running, either because it is finished or it failed due to an error.
    return handler.Result()
}
```

Once the above loops ends, the protocol execution will have either aborted due to an error, or successfully terminated.
The outcome is described by `handler.Result()`.

If an error has occurred, it will be returned here.
A malicious error will be described by a [`protocol.Error`](pkg/protocol/error.go), which may contain information on the responsible party.

- [`protcol.Error`](/pkg/protocol/error.go): Indicates that the protocol has aborted, and may contain the identity of the culprit.
- [`message.Error`](/pkg/message/error.go): Indicates that the message could not be processed, either due to encoding failure, header validation issues, or incorrect routing.

When the protocol successfully completes, the result must be cast to the appropriate type.

### Network

The messages returned by the protocol can be transmitted through a point-to-point network guaranteeing authentication and integrity.
GGCMP21 assumes the availability of a _reliable broadcast_ channel, which guarantees that all participants receive the same broadcasted message.

This assumption is a requirement for identifiable aborts, but since it is harder to guarantee in practice,
we adapted the protocols to use a broadcast channel where each party simply sends the message to all others using a point-to-point channel.

In the future, we may implement protocols that rely on this assumption.
A `Send()` function in this case would look like the following:

```go
func Send(msg *protocol.Message) {
    // A message where Broadcast() is true must be _reliably_ broadcast to all parties.
    // This is a requirement for identifiable aborts.
    if msg.Broadcast() {
        // Send msg reliably to all parties
        return
    }
    // Otherwise, we send the same message to each party individually
    for _, id := range msg.To {
        // Send message to each party using point-to-point communication
    }
}
```

### Keygen

The [`protocols/keygen`](protocols/cmp/keygen) package can be used to perform a distributed key generation.
A [`protocol.Handler`](pkg/protocol/handler.go) is created by specifying the list of `partyIDs` who will receive a share,
and the `selfID` corresponding to this party's ID.

The `threshold` defines the maximum number of corrupt parties tolerated.
That is, the secret key may only be reconstructed using any `threshold+1` different key shares.
This is therefore also the minimum number of participants required to create a signature.

```go
partyIDs := []party.ID{"a", "b", "c", "d", "e"}
selfID := party.ID("a")
threshold := 3

keygenHandler, err := protocol.NewHandler(keygen.StartKeygen(partyIDs, threshold, selfID))
result, err := runProtocolHandler(keygenHandler)
if err != nil {
    // investigate error
}
config := r.(*keygen.Result).Config
```

The [`config`](/protocols/cmp/keygen/config.proto) object contains all necessary data to create a signature.
`Config.PublicKey()` returns an `ecdsa.PublicKey` for which the parties can generate signatures.

### Refresh

Participant's shares of the ECDSA private key can be refreshed after the initial key generation was successfully performed.
It requires all share holders to be present, and the result is a new [`keygen.Config`](/protocols/cmp/keygen/config.go).

The original ECDSA public key remains the same, but the secret is refreshed.

```go
refreshHandler, err := protocol.NewHandler(keygen.StartRefresh(config))
result, err := runProtocolHandler(keygenHandler)
if err != nil {
    // investigate error
}
refreshedConfig := r.(*keygen.Result).Config
```

### Sign

The [`sign`](/protocols/cmp/sign) protocol implements the "3 Round" signing protocol from CGGMP21, without pre-signing or identifiable aborts.
Both these features may be implemented in a future version of `multi-party-sig`.

The resulting signature is a valid ECDSA key.

```go
message := []byte("hello, world")
// since threshold is 3, we need for or more parties to
signers := []party.ID{"a", "b", "c", "d"}

signHandler, err := protocol.NewHandler(sign.StartSign(refreshedConfig, signers, message))
result, err := runProtocolHandler(signHandler)
if err != nil {
    // investigate error
}
signature := r.(*sign.Result).Signature
// verify using standard ecdsa.
r, s := signature.ToRS()
ecdsa.Verify(refreshedConfig.PublicKey(), message, r, s)
```

## Build

`multi-party-sig` requires a custom version of `gogo` which enables the use of `*big.Int` in protobufs.
This version can be compiled by applying the path from [trasc/casttypewith](https://github.com/trasc/protobuf)
It can be installed using the following shell commands:

```shell
git clone https://github.com/gogo/protobuf $GOPATH/src/github.com/gogo/protobuf
cd $GOPATH/src/github.com/gogo/protobuf
git remote add trasc https://github.com/trasc/protobuf.git
git fetch trasc
git merge trasc/casttypewith
cd protoc-gen-gogofaster
go build
cp protoc-gen-gogofaster $GOPATH/bin
```

Once installed, running `make` in the root will regenerate all `.proto` files.

## Intellectual property

This code is copyright (c) Adrian Hamelink and Taurus SA, 2021, and under Apache 2.0 license.

On potential patents: the company that sponsored the development of the CMP
protocol [stated](https://apnews.com/press-release/pr-newswire/26aab91e254bc254d331ceafc20b9859)
that it "will not be applying for patents on this technology."
