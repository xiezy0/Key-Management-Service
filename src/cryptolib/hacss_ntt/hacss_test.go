package hacss_bk_gc

import (
	"fmt"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	//"go.dedis.ch/kyber/v3/group/edwards25519"
	"math/big"
	"testing"
)

// 0.06333949 ns/op 4
// 0.142170651 ns/op 13
// 300881186 ns/op
// 1.581138262 ns/op 31
// 6.039169620 ns/op 49
// 13.526058441 ns/op 64

func BenchmarkHACSS(b *testing.B) {
	for i := 0; i < b.N; i++ {
		//testHacss(16, 5)
		//testHacss(32, 10)
		//testHacss(64, 21)
		testHacssNTT(128, 42)

	}
}

func TestHACSSNTT(t *testing.T) {
	testHacssNTT(7, 2)
}

func BenchmarkSharingNTT(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testSharingNTT(127, 42)
	}
}

func BenchmarkSharing(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testSharing(127, 42)
	}
}

func testSharingNTT(n, t int) {
	p := 2 * t
	//number of threshold
	thre_p := p + 1

	r_0 := GenSecret()

	R_Ploy := GenRPloy(thre_p, r_0)
	R_Ploy_Shares := FastGenRPloyShares(R_Ploy, n)
	//m := nextPowerOfTwo(n)
	//domain := fft.NewDomain(uint64(m)) // 预计算FFT域
	//FastGenSSharePoly(t, n, domain, R_Ploy_Shares)
	//
	S_Share_Poly := GenSSharePoly(t, n, R_Ploy_Shares)
	FastGenSSharePolyShares(S_Share_Poly, n)
}

func testSharing(n, t int) {
	p := 2 * t
	//number of threshold
	thre_p := p + 1

	r_0 := GenSecret()

	R_Ploy := GenRPloy(thre_p, r_0)
	R_Ploy_Shares := GenRPloyShares(R_Ploy, n)
	S_Share_Poly := GenSSharePoly(t, n, R_Ploy_Shares)
	//
	GenSSharePolyShares(S_Share_Poly, n)
}

func testHacssNTT(n, t int) {
	//import a curve
	//g := edwards25519.NewBlakeSHA256Ed25519()

	//total number of players
	//n := 64
	//number of faulty player
	//t := 21
	//recovery threshold
	p := 2 * t
	//number of threshold
	thre_p := p + 1

	fmt.Println("n--", n, "p--", p, "t--", t)
	fmt.Println(" ")

	//**************************************
	//*********This is for the dealer*******
	//*************Send stage***************
	//**************************************

	/* Step 1
	   Randomly choose recovery polynomial R(x)
	   R(x) =r0 + r1x + ... + rpx^p
	*/
	r_0 := GenSecret()
	fmt.Println("r0----", r_0)
	fmt.Println(" ")

	R_Ploy := GenRPloy(thre_p, r_0)
	//fmt.Println("R (x)----", R_Ploy)
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
	S_Share_Poly = GenSSharePoly(t, n, R_Ploy_Shares)
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
	S_Share_Poly_Shares := make([][]*PriShare, 0)
	S_Share_Poly_Shares = GenSSharePolyShares(S_Share_Poly, n)
	fmt.Println("S_Share_Poly_Shares----", S_Share_Poly_Shares)
	fmt.Println(" ")

	S_Share_Poly_Pub_Shares := make([][]*PubShare, 0)
	S_Share_Poly_Pub_Shares = GenSSharePolyPubShares(S_Share_Poly_Commitment, n)
	fmt.Println("S_Share_Poly_Pub_Shares----", S_Share_Poly_Pub_Shares)
	fmt.Println(" ")

	/* Step 6
	   Verify G^S_j[i] == multiply (S'[k])^(i^k)
	*/
	//line 19
	_, _, g1GenAffine, _ := bls12381.Generators()
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			var scalarBigInt big.Int
			S_Share_Poly_Shares[i][j].V.BigInt(&scalarBigInt) // 假设 V 是 fr.Element 类型

			// 3. 执行标量乘法得到 G1 点
			left := new(bls12381.G1Affine).ScalarMultiplication(&g1GenAffine, &scalarBigInt)
			right := S_Share_Poly_Pub_Shares[i][j].V
			if !left.Equal(&right) {
				fmt.Println("line 19 verification is wrong!!!!!!!!!!!!!")
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
		if !left.Equal(&right) {
			fmt.Println("line 20 is wrong!!!!!!!!!!!!!")
		}

	}
	/* Step 8
	   Verify(S'_i,S_i[m]) == 1
	*/
	//line 24
	for m := 0; m < n; m++ {
		for i, share := range S_Share_Poly_Shares[m] {
			if !S_Share_Poly_Commitment[m].Check(share) {
				fmt.Printf("private share %v not valid with respect to the public commitment polynomial", i)
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
		Recovered_S_Share_Poly[i], err = RecoverPriPoly(S_Share_Poly_Shares[i], t+1, n)
		if err != nil {
			fmt.Printf("Fail to recover S_poly[%v]:%v", i, err)
		}
		fmt.Println(" ")
	}
	fmt.Println("recovered_S_Share_Poly----", Recovered_S_Share_Poly)
	fmt.Println(" ")

}
