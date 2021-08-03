---
title: FROST in cmp-ecdsa
author:
  - J.-P. Aumasson
  - A. Hamelink
  - L. C. Meier
date: 14-07-2021
---

We've implemented the [FROST](https://eprint.iacr.org/2020/852.pdf) protocol
inside of this repo. This document details the departures we've made from the protocol
as specified in the paper, along with the additions we've contributed.

# Hedged Deterministic Nonces

When signing, each party needs to generate two random nonces $d_i, e_i \in \mathbb{Z}/(q)$.
Instead of simply sampling them randomly, we instead use a deterministic procedure,
which optionally incorporates randomness:

$$
\begin{aligned}
k &\leftarrow \text{KDF}(s_i) \\
a &\xleftarrow{R} \{0, 1\}^{256} \\
(d_i, e_i) &\leftarrow H_k(\text{SSID} || m || a)
\end{aligned}
$$

$\text{KDF}$ is BLAKE3 in KDF mode, and $H_k$ is BLAKE3 in keyed-hash mode, $\text{SSID}$
is a unique session identifier incorporating context information, like the protocol,
the curve being used, the participants, etc. $m$ is the message, or message hash, and
$s_i$ is the private share for this participant.

Even if $a$ is not generated randomly, the result nonces cannot be computed, because the hash
depends on knowing the secret share $s_i$.

Incorporating a random $a$ protects against fault attacks, by making different different
signings of the same message produce different nonces.

It would likely be safe to include the share $s_i$ in the hash directly, instead
of deriving a hashing key. We think that the deriving the key for a keyed hash is more
defensible from the principle that keys should only be used for a single purpose.

# Chaining Key

For some purposes, it's useful to have an additional bit of randomness alongside
a public key, called a "chaining key". This is useful for key derivation
in BIP-32, for example.

We do this by having each party generate a random byte sequence $c_i$, broadcast
a commitment in round 1, and then decommit in round 2. The final chaining key
is then simply $\bigoplus_i c_i$.

# Taproot compatible signatures

We've implemented a variant of FROST to generate signatures compatible with
[Bitcoin Taproot / BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
The main differences are a specific method for generating the challenge $c$,
but more importantly, the fact that points are encoded for public keys and signatures
by completely discarding the y coordinate. When decoding the x coordinate
into a full point, the point with even y coordinate is always chosen.

The former difference is easy to accomodate, we generate $c$ as:

$$
\text{SHA-256}(\text{SHA-256}(\text{`BIP0340/challenge'}) || 
\text{SHA-256}(\text{`BIP0340/challenge'}) || x(R) || x(P) || m)
$$

as per [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#default-signing).

For the point encoding with y coordinates, we need to modify the protocol in
a few different places to accomodate this.

## Key-Generation

When signing, you conditionally negate your secret key $s$, so that $Y = s \cdot G$
has an even y coordinate. You do this by calculating $Y$, and then negating $s$ if
the y coordinate is odd. In our case, we choose to generate the shared secret so
that it satisfies this property.

Since:

$$
s = \sum_l a_{l0}
$$

Negating $s$ means negating each $a_{l0}$. If we have a polynomial sharing
of $a_{l0}$ as:

$$
f_l(x) = a_{l0} + \ldots + a_{lt} x^t
$$

then negating the polynomial to get $-f_l(x)$ would provide the correct polynomial
sharing of $a_{l0}$. Because our secret share $s_i$ is the sum of these polynomials
evaluated at a certain point, negating the share effectively negates each $a_{i0}$,
and thus effectively negates $s$.

Our modification to key generation is to check if our public key $Y$ has an odd y
coordinate, and if so, negate our own share $s_i$, as well as each
verification share $Y_l := s_l \cdot G$.

Note that you could do all of this when signing, instead of at the end of the
key-generation step. You would reconstruct the public key $Y$ using the verification shares
$Y_i$, and then conditionally negate $s$ as we do above. We find it simpler to integrate
this into the key-generation process.

Regardless, the downside to having to do this is that if a party doesn't respect this
normalization process, you'll only realize this when being unable to
generate a valid signature later.

## Signing

When generating a nonce $k$ for signing, you need to check if the commitment
$R = k \cdot G$ has an even y coordinate, negating $k$ if not. In our case,
we have:

$$
k = \sum_l (d_l + \rho_l e_l)
$$

In order to negate $k$, it suffices to negate each $d_l$ and $e_l$.

We modify the signing protocol at step 4. After calculating the commitment
$R$, we check if it has an odd y coordinate, if so, we negate our own nonces
$d_i$ and $e_i$, as well as the commitment shares $R_l = (d_l + \rho_l e_l) \cdot G$
for each participant $l$.

If a party doesn't participate in this normalization, their response $z_l$ will
fail to validate later.

We also modify this step to calculate the hash in a standardized way.