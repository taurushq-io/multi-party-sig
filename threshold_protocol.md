---
title: Adaptations from CGGMP21
author:
  - J.-P. Aumasson
  - A. Hamelink
  - L. Meier
date: 14-07-2021
---

Our implementation tries to follow the original specification provided in [CGGMP21], but we detail here the modifications we applied.

## Broadcast considerations

Abort identification requires the use of a reliable broadcast channel.
Unfortunately, this condition is hard to meet in practice when the network is modeled as point-to-point.
The protocol generally requires the message from the first round to be reliably broadcast, and so for this step we use the _"echo broadcast"_ from Goldwasser and Lindell.

In the keygen and refresh protocols, the broadcasted message is a commitment, so we need to add an extra round of communication to make sure the parties agree on the first set of messages.
For the signing protocol, the "echo round" can be done in parallel during the second round.

The main disadvantage of this approach is that an adversary can cause an abort by simply sending different messages to different parties.
It therefore makes little sense to implement the indentifiable abort aspect of the signing protocol since an adversary could simply cause an anonymous abort at the start of the protocol.

On the flip side, the user of the library only needs to provide authenticity and integrity between the point-to-point connections between parties.

## Threshold Keygen/Refresh Protocols

In the original paper, the TSS functionality is such that the keygen needs to run the refresh protocol right after.
Moreover, the scheme is not adapted to the threshold case.

We implement a combined $\textcolor{blue}{\text{Keygen}}$/$\textcolor{red}{\text{Refresh}}$ protocol, where we highlight the differences in blue and red respectively.

- Keygen performs the refresh at the same time, so there is no need to two protocols.
- Both protocols now use a threshold $t$ for Shamir secret sharing ($t+1$ secret key shares are required to reconstruct the full secret).
- Optionally, we can also include the extra _El Gamal_ keys $Y$, but since we only care about the 4 round signing protocol, we ignore it.
- If we want to prove this scheme secure, then we would need to change the idea threshold signature functionality. Indeed, it currently assumes refresh is run after keygen. We would need to change the ideal functionality, and adapt the protocol to the $t,n$ case.
- The main difference is that we add a final round of communication where the parties prove in zero-knowledge that they know their new secret share.

We define the SSID as $\textsf{s\textsf{sid}} = (\textsf{sid}, ...)$ where $\textsf{sid} = (q, G, t, n, \{P^{(j)}\}_{j=1}^n)$ and where $...$ is the public information that all parties already know.
When the SSID is used as header for the message, it will most likely be its hash so that we don't send too much information in each message.
Moreover, the computation of this hash should be the same for all parties (i.e. deterministic).

[comment]: <> (F^{&#40;i&#41;}&#40;Z&#41; \gets \left&#40;\sum\_{l=1}^t Z^l \cdot f^{&#40;i&#41;}\_l \right&#41; • G)

#### Round 1

Interpret
$$\textsf{s\textsf{sid}} = (\textsf{sid}, \textcolor{red}{\rho_{old}, \{\textsf{pk}_{old}^{(j)}\}_{j=1}^n, \{N_{old}^{(j)}\}_{j=1}^n, \{s_{1, old}^{(j)}\}_{j=1}^n, \{s_{2,old}^{(j)}\}_{j=1}^n}),$$
where $\textsf{sid} = (q, G, t, n, \{P^{(j)}\}_{j=1}^n)$,
$\textcolor{red}{\text{and retrieve private input \(\textsf{sk}_{old}^{(i)}\)}}$.

- $\textcolor{blue}{\text{Sample  \(x^{(i)} \in \mathbb{F}_q\)}.}$
  - $\textcolor{blue}{X^{(i)} \gets x^{(i)} • G.}$
- Sample $4\kappa$-bit safe primes $p^{(i)}, q^{(i)}$.
  - $N^{(i)} \gets p^{(i)}\cdot q^{(i)}$.
- Sample $\lambda^{(i)} \in \mathbb{Z}^*_{N^{(i)}}$, $r \in \mathbb{Z}^*_{\phi(N^{(i)})}$.
  - $s_1^{(i)} \gets r^{2} \bmod{N^{(i)}}$.
  - $s_2^{(i)} \gets r^{2\lambda} \bmod{N^{(i)}}$.
- Sample $f^{(i)}(Z) \in \mathbb{F}_q[Z]$, such that $f^{(i)}(Z) = \textcolor{blue}{x^{(i)} + }\sum_{l=1}^t f^{(i)}_l Z^l$.
  - $x_i^{(i)} \gets f^{(i)}(i)$
  - Define VSS polynomial coefficients $F^{(i)}_l \gets f^{(i)}_l • G$, for $l = 1, \ldots, t$.
- Sample $a^{(i)} \in \mathbb{F}_q$.
  - $A^{(i)} \gets a^{(i)} • G$.
- Sample $\rho^{(i)}, u^{(i)} \in \{0,1\}^\kappa$.
- $V^{(i)} \gets \textsf{H}(\textsf{s\textsf{sid}}, i, \rho^{(i)}, \{F^{(i)}_l\}_{l=1}^t, \textcolor{blue}{X^{(i)}}, A^{(i)}, N^{(i)}, s_1^{(i)}, s_2^{(i)}, u^{(i)})$.

Broadcast $(\textsf{s\textsf{sid}}, i, V^{(i)})$.

#### _Round 1 (Echo)_

Upon reception of $(\textsf{s\textsf{sid}}, i, V^{(j)})$ from all $P^{(j)}$:

- $E^{(i)} \gets \textsf{H}(\textsf{s\textsf{sid}}, V^{(1)}, \ldots, V^{(n)})$.

Broadcast $(\textsf{s\textsf{sid}}, i, E^{(i)})$.

Upon reception of $(\textsf{s\textsf{sid}}, i, E^{(j)})$ from all $P^{(j)}$:

- $E^{(i)} \stackrel{?}{=} E^{(j)}$.

Deliver $(\textsf{s\textsf{sid}}, i, V^{(j)})$ from all $P^{(j)}$ for the next round.

#### Round 2

Upon reception of $(\textsf{s\textsf{sid}}, i, V^{(j)})$ from all $P^{(j)}$:

Send $(\textsf{s\textsf{sid}}, i, \rho^{(i)}, \{F^{(i)}_l\}_{l=1}^t, \textcolor{blue}{X^{(i)}}, A^{(i)}, N^{(i)}, s_1^{(i)}, s_2^{(i)}, u^{(i)})$ to all.

#### Round 3

Upon reception of $(\textsf{s\textsf{sid}}, j, \rho^{(j)}, \{F^{(j)}_l\}_{l=1}^t, \textcolor{blue}{X^{(j)}}, A^{(j)}, N^{(j)}, s_1^{(j)}, s_2^{(j)}, u^{(j)})$ from $P^{(j)}$:

- $V^{(j)} \stackrel{?}{=} \textsf{H}(\textsf{s\textsf{sid}}, j, \rho^{(j)}, \{F^{(j)}_l\}_{l=1}^t, \textcolor{blue}{X^{(j)}}, A^{(j)}, N^{(j)}, s_1^{(j)}, s_2^{(j)}, u^{(j)})$.
- $\log_2 N^{(j)} \stackrel{?}{=} 8 \kappa$.

If all checks pass:

- $\rho \gets \bigoplus_j \rho^{(j)}$.
- $F^{(j)}(Z) \gets \textcolor{blue}{X^{(j)} + } \sum_{l=1}^t Z^l • F^{(j)}_l$, for all $P^{(j)}$.
- $C^{(i)}_j \gets Enc_j(f^{(i)}(j))$, for all $P^{(j)}$.
- $\psi_{\textsf{mod}}^{(i)} \gets \textsf{Prove}(\textsf{mod}, (\textsf{s\textsf{sid}}, \rho, i), N^{(i)}; (p^{(i)},q^{(i)}))$.
- $\psi_{\textsf{prm}}^{(i)} \gets \textsf{Prove}(\textsf{prm}, (\textsf{s\textsf{sid}}, \rho, i), (N^{(i)}, s_1^{(i)}, s_2^{(i)}); \lambda^{(i)})$.

Send $(\textsf{s\textsf{sid}}, i, \psi_{\textsf{mod}}^{(i)}, \psi_{\textsf{prm}}^{(i)}, C^{(i)}_j)$ to each $P^{(j)}$.

#### Round 4

Upon reception of $(\textsf{s\textsf{sid}}, j, \psi_{\textsf{mod}}^{(j)}, \psi_{\textsf{prm}}^{(j)}, C^{(j)}_j)$ from $P^{(j)}$:

- $x^{(j)}_i \gets Dec_j(C^{(j)}_i) \mod q$.
- $F^{(j)}(i) \stackrel{?}{=} x^{(j)}_i • G$.
- $\textsf{Verify}(\textsf{mod}, (\textsf{s\textsf{sid}}, \rho, j), N^{(j)}; \psi_{\textsf{mod}}^{(j)})$.
- $\textsf{Verify}(\textsf{prm}, (\textsf{s\textsf{sid}}, \rho, j),( N^{(j)}, s_1^{(j)}, s_2^{(j)}); \psi_{\textsf{prm}}^{(j)})$.

If all checks pass:

- $\textsf{sk}^{(i)} \gets  \textcolor{red}{\textsf{sk}_{old}^{(i)} + }\sum_{j=1}^n x^{(j)}_i$.
- $F(Z) \gets \textcolor{red}{\textsf{pk}_{old} +} \sum_{j=1}^n F^{(j)}(Z)$.
- $\textsf{pk} \gets F(0)$.
- $\textsf{pk}^{(j)} \gets F(j)$, for all $P^{(j)}$.
- $\psi_{\textsf{sch}}^{(i)} \gets \textsf{Prove}(\textsf{sch}, (\textsf{s\textsf{sid}}, \rho, i), (\textsf{pk}^{(i)}, A^{(i)}) ;(\textsf{sk}^{(i)}, a^{(i)}))$.

Send $(\textsf{s\textsf{sid}}, i, \psi_{\textsf{sch}}^{(i)})$ to all.

#### Output

Upon reception of $(\textsf{s\textsf{sid}}, i, \psi_{\textsf{sch}}^{(j)})$ from $P^{(j)}$:

- $\textsf{Verify}(\textsf{sch}, (\textsf{s\textsf{sid}}, \rho, j); (\textsf{pk}^{(j)}, A^{(j)}); \psi_{\textsf{sch}}^{(j)})$.

If all checks pass, save:

- Secret $\textsf{sk}^{(i)}, p^{(i)}, q^{(i)}$.
- $\textsf{s\textsf{sid}} \gets (\textsf{sid}, \rho, \{\textsf{pk}^{(j)}\}_{j=1}^n, \{N^{(j)}\}_{j=1}^n, \{s_1^{(j)}\}_{j=1}^n, \{s_2^{(j)}\}_{j=1}^n)$.

### Signing

Interpret $\textsf{s\textsf{sid}} = (\textsf{sid}, \rho, \{\textsf{pk}^{(j)}\}_{j=1}^n, \{N^{(j)}\}_{j=1}^n, \{s_1^{(j)}\}_{j=1}^n, \{s_2^{(j)}\}_{j=1}^n, \{P^{(j)}\}_{j \in S}, m)$,
where $S$ is a subset of $\{ 1, \ldots, n \}$ of size at least $t+1$, and $m$ is the message to be signed.

The protocol goes exactly as before, except that the `Config` will use $S$ to determine Lagrange coefficients and apply them to the set of public keys, as well as the signer's secret share.
Therefore, the resulting shares represent an additive sharing of the secret, and the original protocol can be used.

## Paillier Multiplication proof $\Pi^{\text{mod}}$

This is figure 28 in the CMP paper.

Summarizing, they sample $\alpha, r, s \leftarrow \mathbb{Z}_N^*$. They then calculate:

$$
\begin{aligned}
&Y^{\alpha} \cdot r^N\\
&(1 + N)^{\alpha} s^N
\end{aligned}
$$

Both $s$ and $r$ are used to multiply other values, so sampling from the
unit group makes sense. On the other hand, $\alpha$ is used as an exponent,
so this doesn't make sense. We believe that this is a typo, and that instead
we should have:
$$
\alpha \leftarrow \pm 2^{l + \epsilon}
$$

This matches the generation of other exponents, such as in figure 29.
