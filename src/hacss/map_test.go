package hacss

import (
	"fmt"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"hacss/src/cryptolib"
	"log"
	"testing"
)

func TestMap(test *testing.T) {
	//import a curve
	g := edwards25519.NewBlakeSHA256Ed25519()

	//total number of players
	n := 4
	//number of faulty player
	t := 1
	//recovery threshold
	p := 2 * t
	//number of threshold
	thre_p := p + 1

	var receiveShare IntPolyresultMap
	receiveShare.Init()

	var receivePoint IntPointMap
	receivePoint.Init()

	log.Println("G--", g, "n--", n, "p--", p, "t--", t)
	log.Println(" ")

	//**************************************
	//*********This is for the dealer*******
	//*************Send stage***************
	//**************************************

	/* Step 1
	   Randomly choose recovery polynomial R(x)
	   R(x) =r0 + r1x + ... + rpx^p
	*/
	r_0 := cryptolib.GenSecret(g, g.RandomStream())
	fmt.Println("r0----", r_0)
	fmt.Println(" ")

	R_Ploy := cryptolib.GenRPloy(g, thre_p, r_0, g.RandomStream())
	log.Println("R (x)----", R_Ploy)
	log.Println(" ")
	R_Ploy_Shares := cryptolib.GenRPloyShares(R_Ploy, n) //compute R(1)--R(n)
	log.Printf("R_Ploy_Shares is %v", R_Ploy_Shares)
	for k, v := range R_Ploy_Shares {
		receiveShare.Insert(k, v)
	}

	for i := 0; i < len(R_Ploy_Shares); i++ {
		v, exi := receiveShare.Get(i)
		if !exi {
			log.Printf("Fail receiveShare.Get(%v).", i)
		}
		log.Printf("receiveShare.Get(%v):%v.", i, v)
	}

	G := ComputeExponent(r_0, g)
	log.Printf("G is %v", G)
	receivePoint.Insert(1, G)
	v, exi := receivePoint.Get(1)
	if !exi {
		log.Printf("Fail receivePoint.Get(%v).", 1)
	}
	log.Printf("receiveShare.Get(%v):%v.", 1, v)

	aa := g.Point().Null()
	log.Printf("aa is %v", aa)
	aa.Add(aa, G)
	log.Printf("aa is %v", aa)
}

func TestAddMul(test *testing.T) {

}
