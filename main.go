package main

import (
	"log"
	"time"

	"github.com/gogapopp/blockchain/node"
)

func main() {
	makeNode(":3000", []string{})
	time.Sleep(time.Second * 1)
	makeNode(":4000", []string{":3000"})
	makeNode(":5000", []string{":4000", ":3000"})

	// go func() {
	// 	for {
	// 		time.Sleep(2 * time.Second)
	// 		makeTransaction()
	// 	}
	// }()
	select {}
}

func makeNode(listenAddr string, bootstrapNodes []string) *node.Node {
	n := node.NewNode()
	go n.Start(listenAddr)
	if len(bootstrapNodes) > 0 {
		if err := n.BootstrapNetwork(bootstrapNodes); err != nil {
			log.Fatal(err)
		}
	}
	return n
}

// func makeTransaction() {
// 	client, err := grpc.Dial(":3000", grpc.WithInsecure())
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	c := proto.NewNodeClient(client)

// 	version := &proto.Version{
// 		Version:    "blockchain-0.1",
// 		Height:     1,
// 		ListenAddr: ":4000",
// 	}
// 	_, err = c.Handshake(context.TODO(), version)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// }
