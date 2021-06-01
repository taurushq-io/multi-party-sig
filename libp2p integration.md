# libp2p - tss integration

## Sessions

According to the paper, the sessions should include:

- `sid`: a custom string that is part of the session
- `peers`: a list of `Party.ID`
- `publicShares`: a list public key shares
- `rid`: a random 32 byte string generated during the key generation which is known to all peers (public)
- `aux-info`: individual paillier public key and pedersen stuff

All this information is called the `ssid` and is used as header for all messages.
This is too much information, so instead, we would want to compress it in a way that still makes it useful as message headers (and identifying different sessions).
We can use a hash function for this, but then each party must be able to determine the same session hash without communicating with others.

The `sid` part should probably be a list of the `Peer.ID`s, and would be determined.

### Signing`

In order to be able to advertise that we can sign for a specific public key, we need to create a `round.Session()` which is expected by the current TSS protocol.

1. `GetSSID(publicKey ecdsa.PublicKey) -> (SSID []byte, threshold int)` returns the SSID stored for this public key (it changes after every refresh), and the threshold required.
1. `GetPeerIDsForSSID(SSID []byte) (peers []Peer.ID)` returns the list of `Peer.ID` who we know are associated to this particular SSID.
1. `GetPublicInfo(SSID []byte, peers []Peer.ID) (publicInfo map[Peer.ID]*PublicInfo)` returns a map of public data we have stored for each party.
   1. The struct returned contains the following and would be stored as `(Peer.ID, SSID, PublicInfo)`
   ```go
   type PublicInfo struct {
       ID Peer.ID
       SSID []byte
       ECDSA *curve.Point // share of ECDSA public key
       Paillier *paillier.PublicKey // public Paillier N (may be nil depending on whether we separate keygen and refresh)
       Pedersen *pedersen.Parameters // N,S,T for
   }
   ```
   1. When loading from memory, we do basic checks like:
      1. `!PublicInfo.ECDSA.Equal(curve.NewPointIdentity())`
      1. `PublicInfo.Paillier.IsValid() && PublicInfo.Pedersen.IsValid()`
      1. There are no duplicates _(maybe we can handle these but it would be a bit harder)_
   1. If all checks pass, then return a map.
1. `CreateSession(publicKey ecdsa.PublicKey, SSID []byte, threshold int, publicInfo map[Peer.ID]*PublicInfo) (s *Session, err error)`
   1. Check that we have enough shares given the threshold.
   1. Recompute the public key from the shares, and verify that it is the same. Store the public key in the struct.
   1. Recompute `H(curve, peers, public)` and match it to the SSID.

All of the above would be combined in a single function `GetSession(pk ecdsa.PublicKey) (*Session, error)`

After this, the user provides a struct containing the secret data

```go
type Secret struct {
    ID Peer.ID
    SSID []byte
    ECDSA *curve.Scalar // secret share x_i
    Paillier *paillier.SecretKey // secret Paillier key \phi(N)
}
```

And the party can then validate using `Session.ValidateSecret(Secret) error`.

If this passes, then we can create a new secrvice for this specific public key and SSID.

Note: At the moment, we do not keep the secret key inside the Session.
It may actually make things a bit easier since we could simply do:

```go
func LoadSession(pk *ecdsa.PublicKey) (*Session, error) {
    ssid, t, err := GetSSID(publicKey ecdsa.PublicKey)
    secret, err := GetSecret(ssid []byte)
    peers, err := GetPeerIDsForSSID(SSID []byte)
    public, err := GetPublicInfo(SSID []byte, peers []Peer.ID)
    session, err := CreateSession(publicKey ecdsa.PublicKey, SSID []byte, threshold int, publicInfo map[Peer.ID]*PublicInfo, secret *Secret)
    return session, nil
}
service.AddSession(session)
```

The service then assumes that the given session is correct, and can use the SSID to start listening for messages.

### Sign request

A topic is opened on SSID' = H([]Peer.ID, public key, SSID) where this is the full list of parties.
Any party can broadcast a message that is requested to be singed, and waits for t different responses.
(We need consensus to decide which parties sign lol)
Two options, either we start once every one has repsonded and do a n of n, but this is inefficient.
Otherwise, we could use libp2p metrics to find the best set of peers (clique with minimum total distance between peers)
It is at this phase that the peers run some verification to make sure that the message is correct.

If the algorithm for determining which parties will sign is deterministic, then all parties that agree on a new SSID which restricts the set of signers to only t+1.
The new SSID also ties in the message to be signed.
Each one will then subscribe to the topic for this ssid (the ssid includes the message)

### Keygen

For keygen, things are a bit more tricky since we don't have any existing channel.
If the peers independently have decided who to perform the keygen with

## Keys

- Keys in libp2p are stored as protobuf: [Private](https://github.com/libp2p/go-libp2p-core/blob/7b2888dfdb653943839bf0004c30a24f711c6cb2/crypto/pb/crypto.proto#L19), [Public](https://github.com/libp2p/go-libp2p-core/blob/7b2888dfdb653943839bf0004c30a24f711c6cb2/crypto/pb/crypto.proto#L14)
- Supports ECDSA, Ed25519, Secp256k1

Can we derive `Peer.ID` (`string`) from keyshares instead?

These are essentially already keys, the only problem is Ed25519 keys which depend on some nonce (although we can derive public keys).

In any case, the string `Peer.ID` is the `base58btc` of `SHA256` of something, or in the case of Ed25519 it is the public key.

Maybe this is a bad idea though since that means that we need multiple hosts.

Ideas:

- Store private shares in KeyStore. This may work for public keys, but for fails for Ed25519 private ones.
- More complicated since the public key needs to the then match the ID
- We want the same Peer.ID to have multiple shares.
- Is there another way of easily storing this in the DB?
  - The `KeyBook` interface could do this. We would need our own type of keys

### Storing data

A `PeerStore` stores various information about a given `Peer.ID`. It can either use a database backend or a simple in-memory map.
We could store all keys here using the `PeerMetadata` interface.

For less confusion, we will refer to a signing public key share as a _share_ and _key_ will be that of the dictionary.

The share is only valid for a certain _session_, it should be linked uniquely to a set of public shares (and the full signing public key) and `rid`.

```go
type PublicKeyShare struct {
    sid []byte // H()
    curve string // or elliptic.curve?
    value []byte //
}
```

## Logging

Logging is essential to figure out what is going on, and libp2p uses `import logging "github.com/ipfs/go-log"`.
It is based on [go-logging](https://github.com/whyrusleeping/go-logging).

We can create a context for a given run of the protocol, and report errors appropriately.

## Services

A `Service` is a struct that implements a given protocol.
Two examples (`Identify` and `Pink`) are given in `libp2p/go-libp2p/p2p/protocol`.
We would have `{Keygen, Refresh, Presign, Sign}Service`.
Since our protocols are round-based, we will refer to an arbitrary one as `TSSService`.

At a minimum they should contain a reference to the `host.Host`

```go
type TSSService struct {
    Host host.Host
}

func NewTSSService(h host.Host) *TSSService {
    ps := &TSSService{h}
    h.SetStreamHandler(ID, ps.TSSHandler)
    return ps
}

func (s *Service) AttachSession()
```

Whe

## Using `pubsub`

The `pubsub` library implements a subscribe/publish model over a p2p network.
In our case, we want to be able to broadcast all messages to the relevant parties.
The relevant parties would be those that are either

- Connected and want to generate a key (keygen)
- Connected and have a share of a signing key, but no auxiliary parameters.

The TSS Service could create a new `pubsub` and create topics for various things

### Topics

There would be many topics (string) and most of them would include the ssid to prevent all peers from getting the messages.
To prevent spam, we could perhaps have the peers send a Schnorr proof of knowledge for the curreny key share.
Although this is probably over kill since the peers already identify themselves.

## Questions

- Do we want to have multiple endpoints representing the same signer?
  - Kind of, we want to be able to load balance the signing.
