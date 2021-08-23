package main

import (
	"errors"
	"fmt"
	"sync"

	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"github.com/taurusgroup/multi-party-sig/protocols/example"
	"github.com/taurusgroup/multi-party-sig/protocols/example/xor"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
)

func XOR(id party.ID, ids party.IDSlice, n *test.Network) error {
	h, err := protocol.NewHandler(example.StartXOR(id, ids))
	if err != nil {
		return err
	}
	err = test.HandlerLoop(id, h, n)
	if err != nil {
		return err
	}
	r, err := h.Result()
	if err != nil {
		return err
	}
	h.Log.Info().Hex("xor", r.(xor.Result)).Msg("XOR result")
	return nil
}

func CMPKeygen(id party.ID, ids party.IDSlice, threshold int, n *test.Network, pl *pool.Pool) (*cmp.Config, error) {
	h, err := protocol.NewHandler(cmp.StartKeygen(pl, curve.Secp256k1{}, ids, threshold, id))
	if err != nil {
		return nil, err
	}
	err = test.HandlerLoop(id, h, n)
	if err != nil {
		return nil, err
	}
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func CMPRefresh(c *cmp.Config, n *test.Network, pl *pool.Pool) (*cmp.Config, error) {
	hRefresh, err := protocol.NewHandler(cmp.StartRefresh(pl, c))
	if err != nil {
		return nil, err
	}
	err = test.HandlerLoop(c.ID, hRefresh, n)
	if err != nil {
		return nil, err
	}

	r, err := hRefresh.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func CMPSign(c *cmp.Config, m []byte, signers party.IDSlice, n *test.Network, pl *pool.Pool) error {
	h, err := protocol.NewHandler(cmp.StartSign(pl, c, signers, m))
	if err != nil {
		return err
	}
	err = test.HandlerLoop(c.ID, h, n)
	if err != nil {
		return err
	}

	signResult, err := h.Result()
	if err != nil {
		return err
	}
	signature := signResult.(*ecdsa.Signature)
	if !signature.Verify(c.PublicPoint(), m) {
		return errors.New("failed to verify cmp signature")
	}
	return nil
}

func CMPPreSign(c *cmp.Config, signers party.IDSlice, n *test.Network, pl *pool.Pool) (*ecdsa.PreSignature, error) {
	h, err := protocol.NewHandler(cmp.StartPresign(pl, c, signers))
	if err != nil {
		return nil, err
	}

	if err = test.HandlerLoop(c.ID, h, n); err != nil {
		return nil, err
	}

	signResult, err := h.Result()
	if err != nil {
		return nil, err
	}

	preSignature := signResult.(*ecdsa.PreSignature)
	if err = preSignature.Validate(); err != nil {
		return nil, errors.New("failed to verify cmp presignature")
	}
	return preSignature, nil
}

func CMPPreSignOnline(c *cmp.Config, preSignature *ecdsa.PreSignature, m []byte, n *test.Network) error {
	h, err := protocol.NewHandler(cmp.StartPresignOnline(c, preSignature, m))
	if err != nil {
		return err
	}
	err = test.HandlerLoop(c.ID, h, n)
	if err != nil {
		return err
	}

	signResult, err := h.Result()
	if err != nil {
		return err
	}
	signature := signResult.(*ecdsa.Signature)
	if !signature.Verify(c.PublicPoint(), m) {
		return errors.New("failed to verify cmp signature")
	}
	return nil
}

func FrostKeygen(id party.ID, ids party.IDSlice, threshold int, n *test.Network) (*frost.Config, error) {
	h, err := protocol.NewHandler(frost.StartKeygen(curve.Secp256k1{}, ids, threshold, id))
	if err != nil {
		return nil, err
	}
	err = test.HandlerLoop(id, h, n)
	if err != nil {
		return nil, err
	}
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*frost.Config), nil
}

func FrostSign(c *frost.Config, id party.ID, m []byte, signers party.IDSlice, n *test.Network) error {
	h, err := protocol.NewHandler(frost.StartSign(c, signers, m))
	if err != nil {
		return err
	}
	err = test.HandlerLoop(id, h, n)
	if err != nil {
		return err
	}
	r, err := h.Result()
	if err != nil {
		return err
	}

	signature := r.(frost.Signature)
	if !signature.Verify(c.PublicKey, m) {
		return errors.New("failed to verify frost signature")
	}
	return nil
}

func FrostKeygenTaproot(id party.ID, ids party.IDSlice, threshold int, n *test.Network) (*frost.TaprootConfig, error) {
	h, err := protocol.NewHandler(frost.StartKeygenTaproot(ids, threshold, id))
	if err != nil {
		return nil, err
	}
	err = test.HandlerLoop(id, h, n)
	if err != nil {
		return nil, err
	}
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*frost.TaprootConfig), nil
}
func FrostSignTaproot(c *frost.TaprootConfig, id party.ID, m []byte, signers party.IDSlice, n *test.Network) error {
	h, err := protocol.NewHandler(frost.StartSignTaproot(c, signers, m))
	if err != nil {
		return err
	}
	err = test.HandlerLoop(id, h, n)
	if err != nil {
		return err
	}
	r, err := h.Result()
	if err != nil {
		return err
	}

	signature := r.(taproot.Signature)
	if !c.PublicKey.Verify(signature, m) {
		return errors.New("failed to verify frost signature")
	}
	return nil
}

func All(id party.ID, ids party.IDSlice, threshold int, message []byte, n *test.Network, wg *sync.WaitGroup, pl *pool.Pool) error {
	defer wg.Done()

	// XOR
	err := XOR(id, ids, n)
	if err != nil {
		return err
	}

	// CMP KEYGEN
	keygenConfig, err := CMPKeygen(id, ids, threshold, n, pl)
	if err != nil {
		return err
	}

	// CMP REFRESH
	refreshConfig, err := CMPRefresh(keygenConfig, n, pl)
	if err != nil {
		return err
	}

	// FROST KEYGEN
	frostResult, err := FrostKeygen(id, ids, threshold, n)
	if err != nil {
		return err
	}

	// FROST KEYGEN TAPROOT
	frostResultTaproot, err := FrostKeygenTaproot(id, ids, threshold, n)
	if err != nil {
		return err
	}

	signers := ids[:threshold+1]
	if !signers.Contains(id) {
		n.Quit(id)
		return nil
	}

	// CMP SIGN
	err = CMPSign(refreshConfig, message, signers, n, pl)
	if err != nil {
		return err
	}

	// CMP PRESIGN
	preSignature, err := CMPPreSign(refreshConfig, signers, n, pl)
	if err != nil {
		return err
	}

	// CMP PRESIGN ONLINE
	err = CMPPreSignOnline(refreshConfig, preSignature, message, n)
	if err != nil {
		return err
	}

	// FROST SIGN
	err = FrostSign(frostResult, id, message, signers, n)
	if err != nil {
		return err
	}

	// FROST SIGN TAPROOT
	err = FrostSignTaproot(frostResultTaproot, id, message, signers, n)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	ids := party.IDSlice{"a", "b", "c", "d", "e", "f"}
	threshold := 4
	messageToSign := []byte("hello")

	net := test.NewNetwork(ids)

	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id party.ID) {
			if err := All(id, ids, threshold, messageToSign, net, &wg, pl); err != nil {
				fmt.Println(err)
			}
		}(id)
	}
	wg.Wait()
}
