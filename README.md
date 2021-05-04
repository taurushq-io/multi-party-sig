# cmp-ecdsa

cmp-ecdsa is a Go library that implements the _"UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts"_ [[1]](#1).

## Usage

WIP.

### Keygen

### Refresh

### Sign

For now, we only implement the 4 round interactive signing protocol. 

### Network

The user of the library is responsible for providing a communication layer for sending all messages.

Messages produced by the protocol are encoded as `pb.Message` types, and are serializable using protocol buffers.
They contain all necessary routing information as well as the message content.
The content of the message is assumed to be public and does not need to be encrypted.
However, the routing information may be sensitive and so it is good practice to encrypt the whole message.

Users are responsible for guaranteeing authenticity of the messages.
This requires the 


When the protocol outputs a `pb.Message`, there are 3 different ways this message should be sent to other peers.

#### Send to single

If the `To` field is not empty, then the message is intended for a single recipient.
The message can be sent via a point-to-point link.


#### Basic broadcast/Send to all

#### Reliable broadcast 

When the user of the li message `msg *pb.Message`,  

### General 

Upon reception of a `pb.Message`, the library should check the following:
- The message was correctly signed by 
- The `From` field is consistent with the identity of the node who sent/signed the message
- **TODO** check some HMAC (after refresh, we have a random ID which is shared by all parties)


## TODO 

### Config 

All protocols require the following information:

- Group description
- Party list (sorted list of `party.ID` which are strings)

#### Key Gen

- *Optional:* Initial ECDSAPrivateShare

Output: `keygen.Result`

#### Refresh

- Established ECDSAPrivateShare
- 


## Copyright

(c) 2021 Adrian Hamelink

(c) 2021 Taurus Group

## Reference 

<a name="1">1</a>: Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos Makriyannis, and Udi Peled. “UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts,” 2021. https://eprint.iacr.org/2021/060.

<a name="2">2</a>: Shafi Goldwasser, and Yehuda Lindell. “Secure Multi-Party Computation without Agreement.” Journal of Cryptology 18, no. 3 (July 1, 2005): 247–87. https://doi.org/10.1007/s00145-005-0319-z.
