# Updated Threshold protocols

In CMP, the TSS functionality is such that the keygen needs to run the refresh protocol right after.
Moreover, the scheme is not adapted to the threshold case.
In what follows, we propose two replacement protocols that follow almost exactly the original ones except:

- Keygen performs the refresh at the same time, so there is no need to two protocols
- Both protocols now use a threshold t for Shamir secret sharing
- Optionally, we can also include the extra _El Gamal_ keys $Y$, but since we only care about the 4 round signing protocol, we ignore it.

If we want to prove this scheme secure, then we would need to change the idea threshold signature functionality.
Indeed, it currently assumes refresh is run after keygen.
We would need to change the ideal functionality, and adapt the protocol to the $t,n$ case.

We define the basic SSID as $ssid = (sid, ...)$ where $sid = (q, G, t, n, \{P^{(j)}\}_{j=1}^n)$ and where $...$ is the public information that all parties know.
When the SSID is used as header for the message, it will most likely be its hash so that we don't send too much information in each message.
Moreover, the computation of this hash should be the same for all parties (ie deterministic).

## Threshold Keygen

Interpret $ssid = (sid) = (q, G, t, n, \{P^{(j)}\}_{j=1}^n)$

### Round 1

- Sample $x^{(i)} \in F_q$, set $X^{(i)} = x^{(i)} \cdot G$
- Sample $p^{(i)}, q^{(i)}, N^{(i)}, s_1^{(i)}, s_2^{(i)}, \lambda^{(i)}$ according to Paillier
- Sample $f^{(i)}(X) \in F_q[X]$, such that $f^{(i)}(X) = x^{(i)} + \sum_{l=1}^t f^{(i)}_l X^l$
- Define $\{ F^{(i)}_l = f^{(i)}_l \cdot G \}_{l=0}^t$
- Sample $\{a^{(i)}_l \in F_q\}_{l=0}^t$, define $\{A^{(i)}_l = a^{(i)}_l\}_{l=0}^t$
- Sample $rid^{(i)}, u^{(i)} \in \{0,1\}^\kappa$
- Compute $V^{(i)} = H(ssid, i, rid^{(i)}, \{F^{(i)}_l\}_{l=0}^t, \{A^{(i)}_l\}_{l=0}^t, N^{(i)}, s_1^{(i)}, s_2^{(i)}, u^{(i)})$

Broadcast $(ssid, i, V^{(i)})$

### Round 2

Upon reception of $(ssid, i, V^{(j)})$ from all $P^{(j)}$:

Send $(ssid, i, rid^{(i)}, \{F^{(i)}_l\}_{l=0}^t, \{A^{(i)}_l\}_{l=0}^t, N^{(i)}, s_1^{(i)}, s_2^{(i)}, u^{(i)})$ to all

### Round 3

Upon reception of $(ssid, j, rid^{(j)}, \{F^{(j)}_l\}_{l=0}^t, \{A^{(j)}_l\}_{l=0}^t, N^{(j)}, s_1^{(j)}, s_2^{(j)}, u^{(j)})$:

- Verify $V^{(j)} = H(ssid, j, rid^{(j)}, \{F^{(j)}_l\}_{l=0}^t, \{A^{(j)}_l\}_{l=0}^t, N^{(j)}, s_1^{(j)}, s_2^{(j)}, u^{(j)})$
- Check $\log_2 N^{(j)} = 8 \kappa$
  <!-- - Check $ -->
- Set $F^{(j)}(X) = \sum_{l=0}^t X^l \cdot F^{(j)}_l$

If all checks pass:

- Compute $rid = \bigoplus_j rid^{(j)}$
- Prove:
    - $mod^{(i)} = Prove(mod, (ssid, rid, i), N^{(i)}; (p^{(i)},q^{(i)}))$
    - $prm^{(i)} = Prove(prm, (ssid, rid, i), (N^{(i)}, s_1^{(i)}, s_2^{(i)}); \lambda^{(i)})$
    - $sch^{(i)}_l = Prove(sch, (ssid, rid, i), F^{(i)}_l; A^{(i)}_l ;(f^{(i)}_l, a^{(i)}_l)),\; \forall l = 0, 1, \ldots, t$
- Compute $\{C^{(i)}_j = Enc_j(f^{(i)}(j))\}_{j=1}^n$

Send $(ssid, i, mod^{(i)}, prm^{(i)}, \{sch^{(i)}_l\}_{l=0}^t, C^{(i)}_j)$ to each $P^{(j)}$

### Output

Upon reception of $(ssid, j, mod^{(j)}, prm^{(j)}, \{sch^{(j)}_l\}_{l=0}^t, C^{(j)}_i)$ from $P^{(j)}$:

- Decrypt $x^{(j)}_i = Dec_j(C^{(j)}_i) \mod q$
- Check $F^{(j)}(i) = x^{(j)}_i \cdot G$
- Verify $mod^{(j)}, prm^{(j)}, \{sch^{(j)}_l\}_{l=0}^t$

If all checks pass:

- Compute $sk^{(i)} = \sum_{j=1}^n x^{(j)}_i$
- Set $F(X) = \sum_{j=1}^n F^{(j)}(X)$
- Set $pk = F(0)$
- Compute $pk^{(j)} = F(j), \; \forall P^{(j)}$

Save

- Secret $sk^{(i)}, p^{(i)}, q^{(i)}$
- Public $\{pk^{(j)}\}_{j=1}^n, \{s_1^{(j)}\}_{j=1}^n, \{s_2^{(j)}\}_{j=1}^n$
- $ssid' = sid, rid, \{pk^{(j)}\}_{j=1}^n, \{N^{(j)}\}_{j=1}^n, \{s_1^{(j)}\}_{j=1}^n, \{s_2^{(j)}\}_{j=1}^n$

## Threshold Refresh

Interpret $ssid = (sid, rid, \{pk'^{(j)}\}_{j=1}^n, \{N'^{(j)}\}_{j=1}^n, \{s_1'^{(j)}\}_{j=1}^n, \{s_2'^{(j)}\}_{j=1}^n)$

### Round 1

- Sample $p^{(i)}, q^{(i)}, N^{(i)}, s_1^{(i)}, s_2^{(i)}, \lambda^{(i)}$ according to Paillier
- Sample $f^{(i)}(X) \in F_q[X]$, such that $f^{(i)}(X) = \sum_{l=1}^t f^{(i)}_l X^l$
- Define $\{ F^{(i)}_l = f^{(i)}_l \cdot G \}_{l=1}^t$
- Sample $\{a^{(i)}_l \in F_q\}_{l=1}^t$, define $\{A^{(i)}_l = a^{(i)}_l\}_{l=1}^t$
- Sample $\rho^{(i)}, u^{(i)} \in \{0,1\}^\kappa$
- Compute $V^{(i)} = H(ssid, i, \rho^{(i)}, \{F^{(i)}_l\}_{l=1}^t, \{A^{(i)}_l\}_{l=1}^t, N^{(i)}, s_1^{(i)}, s_2^{(i)}, u^{(i)})$

Broadcast $(ssid, i, V^{(i)})$

### Round 2

Upon reception of $(ssid, i, V^{(j)})$ from all $P^{(j)}$:

Send $(ssid, i, \rho^{(i)}, \{F^{(i)}_l\}_{l=1}^t, \{A^{(i)}_l\}_{l=1}^t, N^{(i)}, s_1^{(i)}, s_2^{(i)}, u^{(i)})$ to all

### Round 3

Upon reception of $(ssid, j, \rho^{(j)}, \{F^{(j)}_l\}_{l=1}^t, \{A^{(j)}_l\}_{l=1}^t, N^{(j)}, s_1^{(j)}, s_2^{(j)}, u^{(j)})$ from $P^{(j)}$:

- Verify $V^{(j)} = H(ssid, j, \rho^{(j)}, \{F^{(j)}_l\}_{l=1}^t, \{A^{(j)}_l\}_{l=1}^t, N^{(j)}, s_1^{(j)}, s_2^{(j)}, u^{(j)})$
- Check $\log_2 N^{(j)} = 8 \kappa$
  <!-- - Check $ -->
- Set $F^{(j)}(X) = \sum_{l=1}^t X^l \cdot F^{(j)}_l$

If all checks pass:

- Compute $\rho = \bigoplus_j \rho^{(j)}$
- Prove:
    - $mod^{(i)} = Prove(mod, (ssid, \rho, i), N^{(i)}; (p^{(i)},q^{(i)}))$
    - $prm^{(i)} = Prove(prm, (ssid, \rho, i), (N^{(i)}, s_1^{(i)}, s_2^{(i)}); \lambda^{(i)})$
    - $sch^{(i)}_l = Prove(sch, (ssid, \rho, i), F^{(i)}_l; A^{(i)}_l ;(f^{(i)}_l, a^{(i)}_l)),\; \forall l = 1, 2, \ldots, t$
- Compute $\{C^{(i)}_j = Enc_j(f^{(i)}(j))\}_{j=1}^n$

Send $(ssid, i, mod^{(i)}, prm^{(i)}, \{sch^{(i)}_l\}_{l=1}^t, C^{(i)}_j)$ to each $P^{(j)}$

### Output

Upon reception of $(ssid, j, mod^{(j)}, prm^{(j)}, \{sch^{(j)}_l\}_{l=1}^t, C^{(j)}_i)$ from $P^{(j)}$:

- Decrypt $x^{(j)}_i = Dec_j(C^{(j)}_i) \mod q$
- Check $F^{(j)}(i) = x^{(j)}_i \cdot G$
- Verify $mod^{(j)}, prm^{(j)}, \{sch^{(j)}_l\}_{l=1}^t$

If all checks pass:

- Compute $sk^{(i)} = sk'^{(i)} + \sum_{j=1}^n x^{(j)}_i$
- Set $F(X) = pk' + \sum_{j=1}^n F^{(j)}(X)$
- Set $pk = F(0)$
- Compute $pk^{(j)} = F(j), \; \forall P^{(j)}$

Save

- Secret $sk^{(i)}, p^{(i)}, q^{(i)}$
- Public $\{pk^{(j)}\}_{j=1}^n, \{s_1^{(j)}\}_{j=1}^n, \{s_2^{(j)}\}_{j=1}^n$
- $ssid' = sid, rid, \{pk^{(j)}\}_{j=1}^n, \{N^{(j)}\}_{j=1}^n, \{s_1^{(j)}\}_{j=1}^n, \{s_2^{(j)}\}_{j=1}^n$

## Signing

Interpret $ssid = (sid, rid, \{pk^{(j)}\}_{j=1}^n, \{N^{(j)}\}_{j=1}^n, \{s_1^{(j)}\}_{j=1}^n, \{s_2^{(j)}\}_{j=1}^n, \{P^{(j)}\}_{j \in S}, m)$,
where $S$ is a subset of $\{ 1, \ldots, n \}$ of size at least $t+1$, and $m$ is the message to be signed.

The protocol goes exactly as before, except that the `Session` will use $S$ to determine Lagrange coefficients and apply them to the set of public keys, as well as the signer's secret share.

Therefore, no modification is needed from the original description.