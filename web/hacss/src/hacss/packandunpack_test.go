package hacss

import (
	"fmt"
	"testing"

	"hacss/src/cryptolib"

	"go.dedis.ch/kyber/v3/suites"
)

func TestPackandUnpack(test *testing.T) {
	//import a curve
	g := suites.MustFind("Ed25519")

	//serilize and deserilize a scalar
	var_scalar := g.Scalar().Pick(g.RandomStream())
	serialized_var_scalar, _ := cryptolib.SerializeScalar(var_scalar)
	deserialized_var_scalar, _ := cryptolib.DeserializeScalar(g.Scalar(), serialized_var_scalar)

	fmt.Println("before serilize---scalar-----", var_scalar)
	fmt.Println("after deserilize---scalar-----", deserialized_var_scalar)

	//serilize and deserilize a point
	var_point := g.Point().Mul(var_scalar, nil)
	fmt.Println("before serilize---point-----", var_point)
	serilized_var_point, _ := cryptolib.SerilizePoint(var_point)
	deserilized_var_point, _ := cryptolib.DeserializePoint(g.Point(), serilized_var_point)
	fmt.Println("after deserilize---point-----", deserilized_var_point)

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
	r_0 := cryptolib.GenSecret(g, g.RandomStream())
	fmt.Println("r0----", r_0)
	fmt.Println(" ")

	R_Ploy := cryptolib.GenRPloy(g, thre_p, r_0, g.RandomStream())
	fmt.Println("R (x)----", R_Ploy)
	fmt.Println(" ")

	/* Step 2
		make polynomial commitment for R(x)
	    R' = (G^r0, G^r1, .. G^rp)
	*/

	R_Ploy_Commitment := cryptolib.GenRPloyCommitment(R_Ploy)
	fmt.Println("R (x) commitment----", R_Ploy_Commitment)
	fmt.Println(" ")

	serilized_pubpoly, _ := R_Ploy_Commitment.SerializePubPoly()
	fmt.Println(cryptolib.DeserilizePubPoly(serilized_pubpoly))

	R_Ploy_Shares := cryptolib.GenRPloyShares(R_Ploy, n)
	fmt.Println("R_Ploy_Shares----", R_Ploy_Shares)
	fmt.Println(" ")

	//Serilize this variable
	fmt.Println("R_Ploy_Shares[0]----", R_Ploy_Shares[0])
	temp_PriShare := R_Ploy_Shares[0]
	serilized_PriShare, _ := cryptolib.SerilizePriShare(temp_PriShare)
	cryptolib.DeserializePriShare(g.Scalar(), serilized_PriShare)

}
