package cryptolib

import (
	"fmt"
	"testing"

	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

func TestHacss(test *testing.T) {
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

	fmt.Println("G--", g, "n--", n, "p--", p, "t--", t)
	fmt.Println(" ")

	//**************************************
	//*********This is for the dealer*******
	//*************Send stage***************
	//**************************************

	/* Step 1
	   Randomly choose recovery polynomial R(x)
	   R(x) =r0 + r1x + ... + rpx^p
	*/
	r_0 := GenSecret(g, g.RandomStream())
	fmt.Println("r0----", r_0)
	fmt.Println(" ")

	R_Ploy := GenRPloy(g, thre_p, r_0, g.RandomStream())
	fmt.Println("R (x)----", R_Ploy)
	fmt.Println(" ")

	/* Step 2
		make polynomial commitment for R(x)
	    R' = (G^r0, G^r1, .. G^rp)
	*/

	R_Ploy_Commitment := GenRPloyCommitment(R_Ploy)
	fmt.Println("R (x) commitment----", R_Ploy_Commitment)
	fmt.Println(" ")

	/* Step 3
	   compute R(j)
	*/
	R_Ploy_Shares := GenRPloyShares(R_Ploy, n)
	fmt.Println("R_Ploy_Shares----", R_Ploy_Shares)
	fmt.Println(" ")

	/* Step 4
	   make polynomial S_j(j)
	   S_j(x) = s_j_0 + s_j_1 x + ... + s_j_t x^t
	   S_j(j) = R(j)
	*/
	S_Share_Poly := make([]*PriPoly, n)
	S_Share_Poly = GenSSharePoly(t, n, g, g.RandomStream(), R_Ploy_Shares)
	fmt.Println("S_Share_Poly----", S_Share_Poly)
	fmt.Println(" ")
	/* Step 5
		   make polynomial commitment for S_j(x)
	       S_j' =(G^sj,0, G^sj,1, ... ,G^sj,t)
	*/
	S_Share_Poly_Commitment := make([]*PubPoly, n)
	S_Share_Poly_Commitment = GenSSharePolyCommitment(S_Share_Poly, n)
	fmt.Println("S_Share_Poly_Commitment----", S_Share_Poly_Commitment)
	fmt.Println(" ")
	//**************************************
	//*********This is for the pi***********
	//*************Echo stage***************
	//**************************************
	S_Share_Poly_Shares := make([][]*share.PriShare, 0)
	S_Share_Poly_Shares = GenSSharePolyShares(S_Share_Poly, n)
	fmt.Println("S_Share_Poly_Shares----", S_Share_Poly_Shares)
	fmt.Println(" ")

	S_Share_Poly_Pub_Shares := make([][]*share.PubShare, 0)
	S_Share_Poly_Pub_Shares = GenSSharePolyPubShares(S_Share_Poly_Commitment, n)
	fmt.Println("S_Share_Poly_Pub_Shares----", S_Share_Poly_Pub_Shares)
	fmt.Println(" ")

	/* Step 6
	   Verify G^S_j[i] == multiply (S'[k])^(i^k)
	*/
	//line 19
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			left := g.Point().Mul(S_Share_Poly_Shares[i][j].V, nil)
			right := S_Share_Poly_Pub_Shares[i][j].V
			if !left.Equal(right) {
				test.Fatal("line 19 verification is wrong!!!!!!!!!!!!!")
			}
		}
	}

	/* Step 7  line 20
	   verify Sj == Rj
	*/
	R_Poly_Pub_Shares := GenRPolyPubShares(R_Ploy_Commitment, n)
	//line 20
	for i := 0; i < n; i++ {
		left := S_Share_Poly_Pub_Shares[i][i].V
		right := R_Poly_Pub_Shares[i].V
		if !left.Equal(right) {
			test.Fatal("line 20 is wrong!!!!!!!!!!!!!")
		}

	}
	/* Step 8
	   Verify(S'_i,S_i[m]) == 1
	*/
	//line 24
	for m := 0; m < n; m++ {
		for i, share := range S_Share_Poly_Shares[m] {
			if !S_Share_Poly_Commitment[m].Check(share) {
				test.Fatalf("private share %v not valid with respect to the public commitment polynomial", i)
			}
		}
	}

	/* Step 9
	   Interpolate S_i
	*/
	//line 31
	Recovered_S_Share_Poly := make([]*PriPoly, n)
	for i := 0; i < n; i++ {
		var err error
		Recovered_S_Share_Poly[i], err = RecoverPriPoly(g, S_Share_Poly_Shares[i], t+1, n)
		if err != nil {
			fmt.Printf("Fail to recover S_poly[%v]:%v", i, err)
		}
		fmt.Println(" ")
	}
	fmt.Println("recovered_S_Share_Poly----", Recovered_S_Share_Poly)
	fmt.Println(" ")

}
