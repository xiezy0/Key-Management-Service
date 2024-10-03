package main

import (
	"encoding/hex"
	"fmt"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
	"hacss/src/hacss"
	"log"
)

func main() {
	var g = edwards25519.NewBlakeSHA256Ed25519()
	n := 4
	thre_p := 3
	sk := make([]string, n)
	sk[0] = "c88be48cd27b7407f8e18a46507e333f9cdfc39e88d7000562d4d5c61e76e407"
	sk[1] = "1ad9b3085acc17a5160b7afcb9d8509d371883d8c04bb6e813fcb203f55b1c07"
	sk[2] = "6c268384e11cbb42353469b223336efbd2504212f9bf6bccc5239040cb415406"
	sk[3] = "be735200696d5ee0535d58688d8d8b596e89014c313421b0774b6d7da1278c05"

	var pk = "65a5b991dab4f3551004a2609f7a046138c566458e45764489e34d03a9dffcd5"

	var shares []*share.PriShare
	for i := 0; i < 4; i++ {
		tmp := new(share.PriShare)
		tmp.V = g.Scalar().Zero()
		tmp.I = i
		tmpByte, _ := hex.DecodeString(sk[i])
		tmp.V.SetBytes(tmpByte)
		shares = append(shares, tmp)
	}
	fmt.Printf("**************************************************************************\n")
	fmt.Printf("******************************* shares ***********************************\n")
	for _, v := range shares {
		fmt.Printf("***%v***\n", v)
	}
	fmt.Printf("**************************************************************************\n")
	//log.Printf("shares:%v", shares)

	reSec, err := share.RecoverSecret(g, shares, thre_p, n)
	if err != nil {
		log.Printf("Fail to recover secret.")
		return
	}
	fmt.Printf("**************************************************************************\n")
	fmt.Printf("********************** Recover secret key SK *****************************\n")
	fmt.Printf("*****%v*****\n", reSec)
	fmt.Printf("**************************************************************************\n")

	tmpG := hacss.ComputeExponent(reSec, g)
	fmt.Printf("**************************************************************************\n")
	fmt.Printf("***************************** Compute g^SK *******************************\n")
	fmt.Printf("*****%v*****\n", tmpG)
	fmt.Printf("**************************************************************************\n")
	if tmpG.String() != pk {
		log.Printf("Recovered secret is not correct.")
		return
	}
	fmt.Printf("**************************************************************************\n")
	fmt.Printf("********************** g^SK = PK, Successful!!! **************************\n")
	fmt.Printf("**************************************************************************\n")
}
