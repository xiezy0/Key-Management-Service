package main

import (
	"encoding/hex"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
	"hacss/src/hacss"
	"log"
)

func main() {
	var g = edwards25519.NewBlakeSHA256Ed25519()
	n := 4
	sk := make([]string, n)
	sk[0] = "da4a6ff4c08b7d187bd1d2c206d1cd50d7ceddc7ed3a6457bbe99549ba12d100"
	sk[1] = "85760fcd48fc70134583bbd1a267e832b81bf10174b4b9452e4de6cdd3b17e04"
	sk[2] = "c37ed24784ba0a96a4dc3df812aeb591aabbfb9611157b3879dd27042ce5b206"
	sk[3] = "9463b86473c64aa099dd593657a4356daeaefd86c65ca82f9c9a5aecc2ac6d07"

	var pk = "f281178173d90b79b6a6c0cf43310d504412cf6108620d6dcc0b95cee59a1e7c"

	var shares []*share.PriShare
	for i := 0; i < 4; i++ {
		tmp := new(share.PriShare)
		tmp.V = g.Scalar().Zero()
		tmp.I = i
		tmpByte, _ := hex.DecodeString(sk[i])
		tmp.V.SetBytes(tmpByte)
		shares = append(shares, tmp)
	}
	log.Printf("shares:%v", shares)

	reSec, err := share.RecoverSecret(g, shares, 3, n)
	if err != nil {
		log.Printf("Fail to recover secret.")
		return
	}

	log.Printf("Recover secret reSec: %v", reSec)

	tmpG := hacss.ComputeExponent(reSec, g)
	log.Printf("Compute g^reSec: %v", tmpG)
	if tmpG.String() != pk {
		log.Printf("Recovered secret is not correct.")
		return
	}
	log.Printf("Successful!!!")
}
