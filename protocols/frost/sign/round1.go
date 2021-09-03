package sign

import (
	"crypto/rand"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/zeebo/blake3"
)

// This round sort of corresponds with Figure 2 of the Frost paper:
//   https://eprint.iacr.org/2020/852.pdf
//
// The main difference is that instead of having a separate pre-processing step,
// we instead have an additional round at the start of the signing step.
// The goal of this round is to generate two nonces, and corresponding commitments.
//
// There are also differences corresponding to the lack of a signing authority,
// namely that these commitments are broadcast, instead of stored with the authority.
type round1 struct {
	*round.Helper
	// taproot indicates whether or not we need to generate Taproot / BIP-340 signatures.
	//
	// If so, we have a few slight tweaks to make around the evenness of points,
	// and we need to make sure to generate our challenge in the correct way. Naturally,
	// we also return a taproot.Signature instead a generic signature.
	taproot bool
	// M is the hash of the message we're signing.
	//
	// This plays the same role as m in the Frost paper. One slight difference
	// is that instead of including the message directly in various hashes,
	// we include the *hash* of that message instead. This provides the same
	// security.
	M messageHash
	// Y is the public key we're signing for.
	Y curve.Point
	// YShares are verification shares for each participant's fraction of the secret key
	//
	// YShares[i] corresponds with Yᵢ in the Frost paper.
	YShares map[party.ID]curve.Point
	// s_i = sᵢ is our private secret share
	s_i curve.Scalar
}

// VerifyMessage implements round.Round.
func (r *round1) VerifyMessage(round.Message) error { return nil }
func (r *round1) StoreMessage(round.Message) error  { return nil }

const deriveHashKeyContext = "github.com/taurusgroup/multi-party-sig/frost 2021-07-30T09:48+00:00 Derive hash Key"

// Finalize implements round.Round.
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// We can think of this as roughly implementing Figure 2. The idea is
	// to generate two nonces (dᵢ, eᵢ) in Z/(q)ˣ, then two commitments
	// Dᵢ = dᵢ * G, Eᵢ = eᵢ * G, and then broadcast them.

	// We use a hedged deterministic process, instead of simply sampling (d_i, e_i):
	//
	//   a = random()
	//   hk = KDF(s_i)
	//   (d_i, e_i) = H_hk(ctx, m, a)
	//
	// This protects against bad randomness, since a constant value for a is still unpredictable,
	// and fault attacks against the hash function, because of the randomness.
	s_iBytes, err := r.s_i.MarshalBinary()
	if err != nil {
		return r, err
	}

	hashKey := make([]byte, 32)
	blake3.DeriveKey(deriveHashKeyContext, s_iBytes[:], hashKey)
	nonceHasher, _ := blake3.NewKeyed(hashKey)
	_, _ = nonceHasher.Write(r.Hash().Sum())
	_, _ = nonceHasher.Write(r.M)
	a := make([]byte, 32)
	_, _ = rand.Read(a)
	_, _ = nonceHasher.Write(a)
	nonceDigest := nonceHasher.Digest()

	d_i := sample.ScalarUnit(nonceDigest, r.Group())
	e_i := sample.ScalarUnit(nonceDigest, r.Group())

	D_i := d_i.ActOnBase()
	E_i := e_i.ActOnBase()

	// Broadcast the commitments
	err = r.BroadcastMessage(out, &broadcast2{D_i: D_i, E_i: E_i})
	if err != nil {
		return r, err
	}
	return &round2{
		round1: r,
		d_i:    d_i,
		e_i:    e_i,
		D:      map[party.ID]curve.Point{r.SelfID(): D_i},
		E:      map[party.ID]curve.Point{r.SelfID(): E_i},
	}, nil
}

// MessageContent implements round.Round.
func (round1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round1) Number() round.Number { return 1 }
