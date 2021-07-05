# cmp-ecdsa

cmp-ecdsa is a Go library that implements the _"UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts"_ [[1]](#1).
For a more detailed description of the protocol, see [threshold_protocol.pdf](threshold_protocol.pdf)

## Usage

### Sessions

Protocol data is stored in a `session.Session` struct.

### Keygen

```go
baseSession, err := session.NewKeygenSession([]party.ID{"a","b","c"}, 2, "a") (*Keygen, error) 
if err != nil {
	//handle err
}
p, err := protocols.NewProtocol(baseSession, refresh.Create)
if err != nil {
    //handle err
}
inChan, outChan, errChan := p.Start()
// TODO handle message passing 
refreshedSession, err := p.GetSession()
if err != nil {
    //handle err
}
```
### Refresh

```go
var oldSession session.Session
if err != nil {
	//handle err
}
p, err := protocols.NewProtocol(baseSession, refresh.Create)
if err != nil {
    //handle err
}
inChan, outChan, errChan := p.Start()
// TODO handle message passing 
refreshedSession, err := p.GetSession()
if err != nil {
    //handle err
}

```
### Sign

For now, we only implement the 4 round interactive signing protocol. 
```go

var (
	refreshedSession session.Session
	message []byte
	signers = []party.ID
)
signSession, err :=  NewSignSession(refreshedSession, signerIDs, message)
if err != nil {
	//handle err
}
p, err := protocols.NewProtocol(signSession, sign.Create)
if err != nil {
    //handle err
}
inChan, outChan, errChan := p.Start()
// TODO handle message passing 
sig, err := p.GetSignature()
if err != nil {
    //handle err
}
```
### Network

The messages returned by the protocol can be transmitted through an authenticated point-to-point network.

## Build

`cmp-ecdsa` requires a custom version of `gogo` which enables the use of `*big.Int` in protobufs. 
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


## Copyright

(c) 2021 Adrian Hamelink

(c) 2021 Taurus Group

## Reference 

<a name="1">1</a>: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos Makriyannis, and Udi Peled. “UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts,” 2021. https://eprint.iacr.org/2021/060.

<a name="2">2</a>: Shafi Goldwasser, and Yehuda Lindell. “Secure Multi-Party Computation without Agreement.” Journal of Cryptology 18, no. 3 (July 1, 2005): 247–87. https://doi.org/10.1007/s00145-005-0319-z.
