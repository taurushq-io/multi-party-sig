package main

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

func main() {
	ctx := context.Background()

	// create a new libp2p Host that listens on a random TCP port
	h1 := makeRandomNode(ctx, 8000)
	h2 := makeRandomNode(ctx, 8080)

	//a1, _ := peer.AddrInfosFromP2pAddrs(h1.Addrs()...)
	a2 := peer.AddrInfo{
		ID:    h2.ID(),
		Addrs: h2.Addrs(),
	}
	err := h1.Connect(ctx, a2)
	if err != nil {
		panic(err)
	}

	fmt.Println(h2.Peerstore().Addrs(h1.ID()))

	//h1.Peerstore().AddAddrs(h2.ID(), h2.Addrs(), peerstore.PermanentAddrTTL)
	//h2.Peerstore().AddAddrs(h1.ID(), h1.Addrs(), peerstore.PermanentAddrTTL)

	//h1.Connect()
	//ps1, err := pubsub.NewFloodSub(ctx, h1)
	//if err != nil {
	//	panic(err)
	//}
	//
	////ps2, err := pubsub.NewFloodSub(ctx, h2)
	//if err != nil {
	//	panic(err)
	//}
	//
	//t1, err := ps1.Join("a")
	//if err != nil {
	//	panic(err)
	//}
	//
	////t1.EventHandler(pubsub.TopicEventHandlerOpt())

	c := make(chan struct{})
	<-c
}

// helper method - create a lib-p2p host to listen on a port
func makeRandomNode(ctx context.Context, port int) host.Host {
	// Ignoring most errors for brevity
	// See echo example for more details and better implementation
	priv, _, _ := crypto.GenerateKeyPair(crypto.Secp256k1, 256)
	listen, _ := ma.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", port))
	h, err := libp2p.New(
		context.Background(),
		libp2p.ListenAddrs(listen),
		libp2p.Identity(priv),
	)
	if err != nil {
		panic(err)
	}

	return h
}
