---
title: Broadcast Issues
author:
  - J.-P. Aumasson
  - A. Hamelink
  - L. Meier
date: 14-07-2021
---

## Broadcast considerations

Abort identification requires the use of a reliable broadcast channel.
Unfortunately, this condition is hard to meet in practice when the network is modeled as point-to-point.
The protocol generally requires the message from the first round to be reliably broadcast, and so for this step we use the _"echo broadcast"_ from Goldwasser and Lindell.

In the keygen and refresh protocols, the broadcasted message is a commitment, so we need to add an extra round of communication to make sure the parties agree on the first set of messages.
For the signing protocol, the "echo round" can be done in parallel during the second round.

The main disadvantage of this approach is that an adversary can cause an abort by simply sending different messages to different parties.
It therefore makes little sense to implement the indentifiable abort aspect of the signing protocol since an adversary could simply cause an anonymous abort at the start of the protocol.

On the flip side, the user of the library only needs to provide authenticity and integrity between the point-to-point connections between parties.
