package hacss

import (
	"fmt"
	"go.dedis.ch/kyber/v3/share"
	"hacss/src/cryptolib"
	"log"
)

func Test() {
	// test algorithm 1 and algorithm 2
	n := 4
	t := 1          //define it
	p := 2 * t      //define it
	thre_p := p + 1 //define it

	//**************************************
	//*********This is for Send stage*******
	//**************************************
	log.Println("**************************************")
	log.Println("**************Start Send.*************")
	log.Println("**************************************")
	//line 1 to 5
	secret := GenerateRandSecret(g, g.RandomStream())
	log.Printf("Secret is %v", secret)
	PolyR := GenerateRandPolynomial(g, thre_p, secret, g.RandomStream())
	log.Printf("Poly R is %v", PolyR)
	R_Poly_Commitment := GeneratePolyCommitment(PolyR)
	log.Printf("R_Poly_Commitment is %v", R_Poly_Commitment)
	//line 5
	G := ComputeExponent(secret, g)
	log.Printf("G is %v", G)

	//line 6 to 8
	R_Ploy_Shares := cryptolib.GenRPloyShares(PolyR, n) //compute R(1)--R(n)
	log.Printf("R_Ploy_Shares is %v", R_Ploy_Shares)
	S_Share_Poly := make([]*cryptolib.PriPoly, n)
	S_Share_Poly = cryptolib.GenSSharePoly(t, n, g, g.RandomStream(), R_Ploy_Shares) //line 6 to 8, generate n poly(s) with degree t, where S(i)=R(i)
	log.Printf("S_Share_Poly is %v", S_Share_Poly)

	//line 9 to 10
	S_Share_Poly_Commitment := make([]*cryptolib.PubPoly, n)
	S_Share_Poly_Commitment = cryptolib.GenSSharePolyCommitment(S_Share_Poly, n) //Generate S_Hat
	log.Printf("S_Share_Poly_Commitment is \n")
	for i := 0; i < n; i++ {
		fmt.Println(S_Share_Poly_Commitment[i])
	}

	//line 11 to 12
	S_Share_Poly_Shares := make([][]*share.PriShare, 0)
	S_Share_Poly_Shares = cryptolib.GenSSharePolyShares(S_Share_Poly, n) //S_Share_Poly_Shares[i] == Si(1)--Si(n)  i.e. Y_i_S = S_Share_Poly_Shares[for j = 1 to n][i]
	log.Printf("S_Share_Poly_Shares is \n")
	for i := 0; i < n; i++ {
		fmt.Println(S_Share_Poly_Shares[i])
	}
	var y_to_S [][]*share.PriShare
	for i := 0; i < n; i++ {
		var y_i_to_S []*share.PriShare
		for j := 0; j < n; j++ {
			y_i_to_S = append(y_i_to_S, S_Share_Poly_Shares[j][i])
		}
		y_to_S = append(y_to_S, y_i_to_S)
	}
	log.Printf("y_to_S is \n")
	for i := 0; i < n; i++ {
		fmt.Println(y_to_S[i])
	}

	//line 13 to 14
	var data [][]byte
	//todo: serialize R_Poly_Commitment, S_Share_Poly_Commitment[i], and append to "data", mow a wrong way
	//
	tmp, _ := R_Poly_Commitment.SerializePubPoly()
	data = append(data, tmp)
	for _, v := range S_Share_Poly_Commitment {
		tmp, err := v.SerializePubPoly() //
		if err != nil {
			log.Printf("Commitment Serialize Err: %v", err)
		}
		data = append(data, tmp)
	}
	//log.Printf("data is %v", data)

	C, branches, idxresult, suc := GenerateVectorCommitment(data)
	if !suc {
		log.Printf("Fail to get merkle branch when start HACSS for instance!")
		return
	}
	log.Printf("Vector commitment root is %v", C)
	R_hat_witness := Witness{
		PolyCommit:   R_Poly_Commitment,
		MerkleBranch: branches[0],
		MerkleIndex:  idxresult[0],
	}
	log.Printf("R_hat_witness is %v", R_hat_witness)

	var S_hat_witness []Witness
	for i := 1; i <= n; i++ {
		tmpWitness := Witness{
			PolyCommit:   *S_Share_Poly_Commitment[i-1],
			MerkleBranch: branches[i],
			MerkleIndex:  idxresult[i],
		}
		S_hat_witness = append(S_hat_witness, tmpWitness)
	}

	//line 15 to 16
	var AllSet []SetSend
	for i := 0; i < n; i++ {
		set_i := SetSend{
			C:           C,
			G:           G,
			RHatWitness: R_hat_witness,
			SHatWitness: S_hat_witness,
			YiS:         y_to_S[i],
		}
		AllSet = append(AllSet, set_i)
	}

	//**************************************
	//*********This is for Echo stage*******
	//**************************************
	log.Println("**************************************")
	log.Println("**************Start Echo.*************")
	log.Println("**************************************")
	var AllInfo []InfoSend
	for i, set_i := range AllSet {
		//line 18
		fragByte, _ := set_i.RHatWitness.PolyCommit.SerializePubPoly()
		if !VerifyMerkleRoot(fragByte, set_i.RHatWitness.MerkleBranch, set_i.RHatWitness.MerkleIndex, set_i.C) {
			log.Printf("[%v] Fatal to verify merkel root for RHat", i)
			return
		}
		for k, wit := range set_i.SHatWitness {
			fragByte, _ = wit.PolyCommit.SerializePubPoly()
			if !VerifyMerkleRoot(fragByte, wit.MerkleBranch, wit.MerkleIndex, set_i.C) {
				log.Printf("[%v] Fatal to verify merkel root for SHat[%v]", i, k)
				return
			}
		}

		//line 19
		for j := 1; j <= n; j++ {
			if !PVerify(set_i.SHatWitness[j-1].PolyCommit, set_i.YiS[j-1]) {
				log.Printf("[%v] Fatal PVerify for %v", i, j)
				return
			}
		}

		//line 20
		for j := 0; j < n-1; j++ {
			if !VerifyDiagonal(set_i.RHatWitness.PolyCommit, set_i.SHatWitness[j].PolyCommit, j) {
				log.Printf("[%v] Fatal VerifyDiagonal for %v", i, j)
				return
			}
		}

		//line 21 to 22
		for i := 0; i < n; i++ {
			//Pi sends to Pm
			infoIM := InfoSend{
				C:        set_i.C,
				G:        set_i.G,
				SWitness: set_i.SHatWitness[i],
				PResult:  set_i.YiS[i],
			}
			AllInfo = append(AllInfo, infoIM)
		}
	}
	log.Printf("Success verify all set send to each replica.\n\n")

	//**************************************
	//*********This is for Ready stage******
	//**************************************
	log.Println("**************************************")
	log.Println("**************Start Ready.************")
	log.Println("**************************************")

	for i := 0; i < n-1; i++ {
		infoMI := AllInfo[i]
		//line24
		fragByte, _ := infoMI.SWitness.PolyCommit.SerializePubPoly()
		if !VerifyMerkleRoot(fragByte, infoMI.SWitness.MerkleBranch, infoMI.SWitness.MerkleIndex, infoMI.C) {
			log.Printf("[%v] Fatal to verify merkel root for Echo", i)
			return
		}

		if !PVerify(infoMI.SWitness.PolyCommit, infoMI.PResult) {
			log.Printf("[%v] Fatal PVerify of Echo", i)
			return
		}
	}
	log.Printf("Success verify all info send to each replica.\n\n")

	//**************************************
	//********This is for Deliver stage*****
	//**************************************
	log.Println("**************************************")
	log.Println("*************Start Deliver.***********")
	log.Println("**************************************")
	var AllShare [][]*share.PriShare
	for i := 0; i < n; i++ {
		var SShare []*share.PriShare
		for j := 0; j < n; j++ {
			SShare = append(SShare, y_to_S[j][i])
		}
		AllShare = append(AllShare, SShare)
	}

	var simulateShare []*share.PriShare
	for i := 0; i < n; i++ {
		//line 32
		poly, err := InterpolatePolynomial(g, AllShare[i], t+1, n)
		if err != nil {
			log.Printf("[%v]Fail to recover share poly.", i)
		}
		myShare := ComputePolyValue(poly, i+1)
		if !myShare.V.Equal(R_Ploy_Shares[i].V) {
			log.Printf("[%v]Fail to recover share.", i)
		}
		simulateShare = append(simulateShare, myShare)
		log.Printf("[%v] Share is %v", i, myShare)
	}
	log.Printf("Success recover all share.\n\n")

	//**************************************
	//********This is for recover stage*****
	//***********Algorithm 2****************
	//**************************************
	log.Println("**************************************")
	log.Println("*************Start recover.***********")
	log.Println("**************************************")
	reRpoly, err := InterpolatePolynomial(g, simulateShare, thre_p, n)
	if err != nil {
		log.Printf("Fail to recover R poly.%v", err)
	}
	log.Printf("Recover poly R is %v", reRpoly)
	reSec, err := share.RecoverSecret(g, simulateShare, thre_p, n)
	if err != nil {
		log.Printf("Fail to recover secret.%v", err)
	}
	log.Printf("Recover secret is %v", reSec)
	log.Printf("Recover secret result:%v", reSec.Equal(secret))

	log.Println("**************************************")
	log.Println("************Succeed Verify.***********")
	log.Println("**************************************")
}

// TestMul test algorithm 3, simulate 4 node sharing secret.
//
// Replica i shares si and replica j receives si,j.
//
// Replica i recover the secret key is ski = s0,i + s1,i + ...+ sn,i.
//
// All replicas recover the same public key PK = g^(s1 + s2 + ... + sn).
//
// Recover the whole secret key SK by Lagrange's interpolation utilizing arbitrary 2f+1 ski, and hold g^SK = PK
func TestMul() {

	n := 4
	t := 1          //define it
	p := 2 * t      //define it
	thre_p := p + 1 //define it

	//var AllRecoverShare [][]*share.PriShare
	var AllReceivedG IntPointMap
	AllReceivedG.Init()
	var AllRecoverShare []IntPolyresultMap

	for ii := 0; ii < n; ii++ {
		var tmp IntPolyresultMap
		tmp.Init()
		AllRecoverShare = append(AllRecoverShare, tmp)
	}

	for cid := 0; cid < n; cid++ {
		//**************************************
		//*********This is for Send stage*******
		//**************************************
		log.Println("**************************************")
		log.Println("**************Start Send.*************")
		log.Println("**************************************")
		//line 1 to 5
		secret := GenerateRandSecret(g, g.RandomStream())
		log.Printf("Secret is %v", secret)
		PolyR := GenerateRandPolynomial(g, thre_p, secret, g.RandomStream())
		log.Printf("Poly R is %v", PolyR)
		R_Poly_Commitment := GeneratePolyCommitment(PolyR)
		log.Printf("R_Poly_Commitment is %v", R_Poly_Commitment)
		//line 5
		G := ComputeExponent(secret, g)
		log.Printf("G is %v", G)

		//line 6 to 8
		R_Ploy_Shares := cryptolib.GenRPloyShares(PolyR, n) //compute R(1)--R(n)
		log.Printf("R_Ploy_Shares is %v", R_Ploy_Shares)
		S_Share_Poly := make([]*cryptolib.PriPoly, n)
		S_Share_Poly = cryptolib.GenSSharePoly(t, n, g, g.RandomStream(), R_Ploy_Shares) //line 6 to 8, generate n poly(s) with degree t, where S(i)=R(i)
		log.Printf("S_Share_Poly is %v", S_Share_Poly)

		//line 9 to 10
		S_Share_Poly_Commitment := make([]*cryptolib.PubPoly, n)
		S_Share_Poly_Commitment = cryptolib.GenSSharePolyCommitment(S_Share_Poly, n) //Generate S_Hat
		log.Printf("S_Share_Poly_Commitment is \n")
		for i := 0; i < n; i++ {
			fmt.Println(S_Share_Poly_Commitment[i])
		}

		//line 11 to 12
		S_Share_Poly_Shares := make([][]*share.PriShare, 0)
		S_Share_Poly_Shares = cryptolib.GenSSharePolyShares(S_Share_Poly, n) //S_Share_Poly_Shares[i] == Si(1)--Si(n)  i.e. Y_i_S = S_Share_Poly_Shares[for j = 1 to n][i]
		log.Printf("S_Share_Poly_Shares is \n")
		for i := 0; i < n; i++ {
			fmt.Println(S_Share_Poly_Shares[i])
		}
		var y_to_S [][]*share.PriShare
		for i := 0; i < n; i++ {
			var y_i_to_S []*share.PriShare
			for j := 0; j < n; j++ {
				y_i_to_S = append(y_i_to_S, S_Share_Poly_Shares[j][i])
			}
			y_to_S = append(y_to_S, y_i_to_S)
		}
		log.Printf("y_to_S is \n")
		for i := 0; i < n; i++ {
			fmt.Println(y_to_S[i])
		}

		//line 13 to 14
		var data [][]byte
		//todo: serialize R_Poly_Commitment, S_Share_Poly_Commitment[i], and append to "data", mow a wrong way
		//
		tmp, _ := R_Poly_Commitment.SerializePubPoly()
		data = append(data, tmp)
		for _, v := range S_Share_Poly_Commitment {
			tmp, err := v.SerializePubPoly() //
			if err != nil {
				log.Printf("Commitment Serialize Err: %v", err)
			}
			data = append(data, tmp)
		}
		//log.Printf("data is %v", data)

		C, branches, idxresult, suc := GenerateVectorCommitment(data)
		if !suc {
			log.Printf("Fail to get merkle branch when start HACSS for instance!")
			return
		}
		log.Printf("Vector commitment root is %v", C)
		R_hat_witness := Witness{
			PolyCommit:   R_Poly_Commitment,
			MerkleBranch: branches[0],
			MerkleIndex:  idxresult[0],
		}
		log.Printf("R_hat_witness is %v", R_hat_witness)

		var S_hat_witness []Witness
		for i := 1; i <= n; i++ {
			tmpWitness := Witness{
				PolyCommit:   *S_Share_Poly_Commitment[i-1],
				MerkleBranch: branches[i],
				MerkleIndex:  idxresult[i],
			}
			S_hat_witness = append(S_hat_witness, tmpWitness)
		}

		//line 15 to 16
		var AllSet []SetSend
		for i := 0; i < n; i++ {
			set_i := SetSend{
				C:           C,
				G:           G,
				RHatWitness: R_hat_witness,
				SHatWitness: S_hat_witness,
				YiS:         y_to_S[i],
			}
			AllSet = append(AllSet, set_i)
		}

		//**************************************
		//*********This is for Echo stage*******
		//**************************************
		log.Println("**************************************")
		log.Println("**************Start Echo.*************")
		log.Println("**************************************")
		var AllInfo []InfoSend
		for i, set_i := range AllSet {
			//line 18
			fragByte, _ := set_i.RHatWitness.PolyCommit.SerializePubPoly()
			if !VerifyMerkleRoot(fragByte, set_i.RHatWitness.MerkleBranch, set_i.RHatWitness.MerkleIndex, set_i.C) {
				log.Printf("[%v] Fatal to verify merkel root for RHat", i)
				return
			}
			for k, wit := range set_i.SHatWitness {
				fragByte, _ = wit.PolyCommit.SerializePubPoly()
				if !VerifyMerkleRoot(fragByte, wit.MerkleBranch, wit.MerkleIndex, set_i.C) {
					log.Printf("[%v] Fatal to verify merkel root for SHat[%v]", i, k)
					return
				}
			}

			//line 19
			for j := 1; j <= n; j++ {
				if !PVerify(set_i.SHatWitness[j-1].PolyCommit, set_i.YiS[j-1]) {
					log.Printf("[%v] Fatal PVerify for %v", i, j)
					return
				}
			}

			//line 20
			for j := 0; j < n-1; j++ {
				if !VerifyDiagonal(set_i.RHatWitness.PolyCommit, set_i.SHatWitness[j].PolyCommit, j) {
					log.Printf("[%v] Fatal VerifyDiagonal for %v", i, j)
					return
				}
			}

			//line 21 to 22
			for i := 0; i < n; i++ {
				//Pi sends to Pm
				infoIM := InfoSend{
					C:        set_i.C,
					G:        set_i.G,
					SWitness: set_i.SHatWitness[i],
					PResult:  set_i.YiS[i],
				}
				AllInfo = append(AllInfo, infoIM)
			}
		}
		log.Printf("Success verify all set send to each replica.\n\n")

		//**************************************
		//*********This is for Ready stage******
		//**************************************
		log.Println("**************************************")
		log.Println("**************Start Ready.************")
		log.Println("**************************************")

		for i := 0; i < n-1; i++ {
			infoMI := AllInfo[i]
			//line24
			fragByte, _ := infoMI.SWitness.PolyCommit.SerializePubPoly()
			if !VerifyMerkleRoot(fragByte, infoMI.SWitness.MerkleBranch, infoMI.SWitness.MerkleIndex, infoMI.C) {
				log.Printf("[%v] Fatal to verify merkel root for Echo", i)
				return
			}

			if !PVerify(infoMI.SWitness.PolyCommit, infoMI.PResult) {
				log.Printf("[%v] Fatal PVerify of Echo", i)
				return
			}
		}
		log.Printf("Success verify all info send to each replica.\n\n")

		//**************************************
		//********This is for Deliver stage*****
		//**************************************
		log.Println("**************************************")
		log.Println("*************Start Deliver.***********")
		log.Println("**************************************")
		var AllShare [][]*share.PriShare
		for i := 0; i < n; i++ {
			var SShare []*share.PriShare
			for j := 0; j < n; j++ {
				SShare = append(SShare, y_to_S[j][i])
			}
			AllShare = append(AllShare, SShare)
		}

		//var simulateShare []*share.PriShare
		for i := 0; i < n; i++ {
			//line 32
			poly, err := InterpolatePolynomial(g, AllShare[i], t+1, n)
			if err != nil {
				log.Printf("[%v]Fail to recover share poly.", i)
			}
			myShare := ComputePolyValue(poly, i+1)
			if !myShare.V.Equal(R_Ploy_Shares[i].V) {
				log.Printf("[%v]Fail to recover share.", i)
			}
			//simulateShare = append(simulateShare, myShare)
			AllRecoverShare[i].Insert(cid, myShare)
			log.Printf("[%v] Share is %v", i, myShare)
		}
		log.Printf("Success recover all share.\n\n")

		AllReceivedG.Insert(cid, G)
	}

	//**************************************
	//********This is for verify stage*****
	//**************************************
	log.Println("**************************************")
	log.Println("*************Start verify 3.**********")
	log.Println("**************************************")
	var AllSecret []*share.PriShare //each replica compute,for replica 0, AllSecret[0] = s0,0+s1,0+s2,0+s3,0
	for i := 0; i < n; i++ {
		var secretKey = new(share.PriShare)
		secretKey.V = g.Scalar().Zero()
		for _, myShare := range AllRecoverShare[i].GetAll() {
			//log.Printf("myShare.I %v", myShare.I)
			secretKey.I = myShare.I
			secretKey.V = myShare.V.Add(secretKey.V, myShare.V)
		}
		AllSecret = append(AllSecret, secretKey)
	}
	reSec, err := share.RecoverSecret(g, AllSecret, thre_p, n)
	if err != nil {
		log.Printf("Fail to recover secret.")
		return
	}
	log.Printf("Recover secret reSec: %v", reSec)
	var pubKey = g.Point().Null()
	for _, pub := range AllReceivedG.GetAll() {
		log.Printf("G %v", pub)
		pubKey.Add(pubKey, pub)
	}
	log.Printf("Recover public: %v", pubKey)

	tmpG := ComputeExponent(reSec, g)
	log.Printf("Compute g^reSec: %v", tmpG)
	if !tmpG.Equal(pubKey) {
		log.Printf("Recovered secret is not correct.")
		return
	}
	log.Printf("g^reSec == pubKey: %v", tmpG.Equal(pubKey))

	log.Println("**************************************")
	log.Println("************Succeed Verify.***********")
	log.Println("**************************************")
}

func TestWithSerialize() {
	// test algorithm 1 and algorithm 2
	n := 4
	t := 1          //define it
	p := 2 * t      //define it
	thre_p := p + 1 //define it

	//**************************************
	//*********This is for Send stage*******
	//**************************************
	log.Println("**************************************")
	log.Println("**************Start Send.*************")
	log.Println("**************************************")
	//line 1 to 5
	secret := GenerateRandSecret(g, g.RandomStream())
	log.Printf("Secret is %v", secret)
	PolyR := GenerateRandPolynomial(g, thre_p, secret, g.RandomStream())
	log.Printf("Poly R is %v", PolyR)
	R_Poly_Commitment := GeneratePolyCommitment(PolyR)
	log.Printf("R_Poly_Commitment is %v", R_Poly_Commitment)
	//line 5
	G := ComputeExponent(secret, g)
	log.Printf("G is %v", G)

	//line 6 to 8
	R_Ploy_Shares := cryptolib.GenRPloyShares(PolyR, n) //compute R(1)--R(n)
	log.Printf("R_Ploy_Shares is %v", R_Ploy_Shares)
	S_Share_Poly := make([]*cryptolib.PriPoly, n)
	S_Share_Poly = cryptolib.GenSSharePoly(t, n, g, g.RandomStream(), R_Ploy_Shares) //line 6 to 8, generate n poly(s) with degree t, where S(i)=R(i)
	log.Printf("S_Share_Poly is %v", S_Share_Poly)

	//line 9 to 10
	S_Share_Poly_Commitment := make([]*cryptolib.PubPoly, n)
	S_Share_Poly_Commitment = cryptolib.GenSSharePolyCommitment(S_Share_Poly, n) //Generate S_Hat
	log.Printf("S_Share_Poly_Commitment is \n")
	for i := 0; i < n; i++ {
		fmt.Println(S_Share_Poly_Commitment[i])
	}

	//line 11 to 12
	S_Share_Poly_Shares := make([][]*share.PriShare, 0)
	S_Share_Poly_Shares = cryptolib.GenSSharePolyShares(S_Share_Poly, n) //S_Share_Poly_Shares[i] == Si(1)--Si(n)  i.e. Y_i_S = S_Share_Poly_Shares[for j = 1 to n][i]
	log.Printf("S_Share_Poly_Shares is \n")
	for i := 0; i < n; i++ {
		fmt.Println(S_Share_Poly_Shares[i])
	}
	var y_to_S [][]*share.PriShare
	for i := 0; i < n; i++ {
		var y_i_to_S []*share.PriShare
		for j := 0; j < n; j++ {
			y_i_to_S = append(y_i_to_S, S_Share_Poly_Shares[j][i])
		}
		y_to_S = append(y_to_S, y_i_to_S)
	}
	log.Printf("y_to_S is \n")
	for i := 0; i < n; i++ {
		fmt.Println(y_to_S[i])
	}

	//line 13 to 14
	var data [][]byte
	//todo: serialize R_Poly_Commitment, S_Share_Poly_Commitment[i], and append to "data", mow a wrong way
	//
	tmp, _ := R_Poly_Commitment.SerializePubPoly()
	data = append(data, tmp)
	for _, v := range S_Share_Poly_Commitment {
		tmp, err := v.SerializePubPoly() //
		if err != nil {
			log.Printf("Commitment Serialize Err: %v", err)
		}
		data = append(data, tmp)
	}
	//log.Printf("data is %v", data)

	C, branches, idxresult, suc := GenerateVectorCommitment(data)
	if !suc {
		log.Printf("Fail to get merkle branch when start HACSS for instance!")
		return
	}
	log.Printf("Vector commitment root is %v", C)
	R_hat_witness := Witness{
		PolyCommit:   R_Poly_Commitment,
		MerkleBranch: branches[0],
		MerkleIndex:  idxresult[0],
	}
	log.Printf("R_hat_witness is %v", R_hat_witness)

	var S_hat_witness []Witness
	for i := 1; i <= n; i++ {
		tmpWitness := Witness{
			PolyCommit:   *S_Share_Poly_Commitment[i-1],
			MerkleBranch: branches[i],
			MerkleIndex:  idxresult[i],
		}
		S_hat_witness = append(S_hat_witness, tmpWitness)
	}

	//line 15 to 16
	var AllSet [][]byte
	for i := 0; i < n; i++ {
		set_i := SetSend{
			C:           C,
			G:           G,
			RHatWitness: R_hat_witness,
			SHatWitness: S_hat_witness,
			YiS:         y_to_S[i],
		}
		tmpByte, err := set_i.SerializeSetSend()
		if err != nil {
			log.Printf("Fail to serialize setSend %d: %v", i, err)
			return
		}
		AllSet = append(AllSet, tmpByte)
	}

	//**************************************
	//*********This is for Echo stage*******
	//**************************************
	log.Println("**************************************")
	log.Println("**************Start Echo.*************")
	log.Println("**************************************")
	var AllInfo [][]byte
	for i, set_i_byte := range AllSet {
		//line 18
		set_i := DeserializeSetSend(set_i_byte)
		fragByte, _ := set_i.RHatWitness.PolyCommit.SerializePubPoly()
		if !VerifyMerkleRoot(fragByte, set_i.RHatWitness.MerkleBranch, set_i.RHatWitness.MerkleIndex, set_i.C) {
			log.Printf("[%v] Fatal to verify merkel root for RHat", i)
			return
		}
		for k, wit := range set_i.SHatWitness {
			fragByte, _ = wit.PolyCommit.SerializePubPoly()
			if !VerifyMerkleRoot(fragByte, wit.MerkleBranch, wit.MerkleIndex, set_i.C) {
				log.Printf("[%v] Fatal to verify merkel root for SHat[%v]", i, k)
				return
			}
		}

		//line 19
		for j := 1; j <= n; j++ {
			if !PVerify(set_i.SHatWitness[j-1].PolyCommit, set_i.YiS[j-1]) {
				log.Printf("[%v] Fatal PVerify for %v", i, j)
				return
			}
		}

		//line 20
		for j := 0; j < n-1; j++ {
			if !VerifyDiagonal(set_i.RHatWitness.PolyCommit, set_i.SHatWitness[j].PolyCommit, j) {
				log.Printf("[%v] Fatal VerifyDiagonal for %v", i, j)
				return
			}
		}

		//line 21 to 22
		for i := 0; i < n; i++ {
			//Pi sends to Pm
			infoIM := InfoSend{
				C:        set_i.C,
				G:        set_i.G,
				SWitness: set_i.SHatWitness[i],
				PResult:  set_i.YiS[i],
			}
			tmpByte, err := infoIM.SerializeInfoSend()
			if err != nil {
				log.Printf("Fail to serialize infoSend %d: %v", i, err)
				return
			}
			AllInfo = append(AllInfo, tmpByte)
		}
	}
	log.Printf("Success verify all set send to each replica.\n\n")

	//**************************************
	//*********This is for Ready stage******
	//**************************************
	log.Println("**************************************")
	log.Println("**************Start Ready.************")
	log.Println("**************************************")

	for i := 0; i < n-1; i++ {
		infoMI_byte := AllInfo[i]
		//line24
		infoMI := DeserializeInfoSend(infoMI_byte)
		fragByte, _ := infoMI.SWitness.PolyCommit.SerializePubPoly()
		if !VerifyMerkleRoot(fragByte, infoMI.SWitness.MerkleBranch, infoMI.SWitness.MerkleIndex, infoMI.C) {
			log.Printf("[%v] Fatal to verify merkel root for Echo", i)
			return
		}

		if !PVerify(infoMI.SWitness.PolyCommit, infoMI.PResult) {
			log.Printf("[%v] Fatal PVerify of Echo", i)
			return
		}
	}
	log.Printf("Success verify all info send to each replica.\n\n")

	//**************************************
	//********This is for Deliver stage*****
	//**************************************
	log.Println("**************************************")
	log.Println("*************Start Deliver.***********")
	log.Println("**************************************")
	//var AllShare [][]*share.PriShare
	var AllShare []IntPolyresultMap

	for i := 0; i < n; i++ {
		//var SShare []*share.PriShare
		var SShare IntPolyresultMap
		SShare.Init()
		for j := 0; j < n; j++ {
			SShare.Insert(j, y_to_S[j][i])
		}
		AllShare = append(AllShare, SShare)
	}

	var simulateShare []*share.PriShare
	for i := 0; i < n; i++ {
		//line 32
		receiveSharesMap := AllShare[i].GetAll()
		var receiveShares []*share.PriShare
		for _, v := range receiveSharesMap {
			receiveShares = append(receiveShares, v)
		}
		log.Printf("receiveShares: %v ", receiveShares)
		log.Printf("receiveShares: %v ", receiveShares)
		poly, err := InterpolatePolynomial(g, receiveShares, t+1, n)
		if err != nil {
			log.Printf("[%v]Fail to recover share poly.", i)
			return
		}
		myShare := ComputePolyValue(poly, i+1)
		if !myShare.V.Equal(R_Ploy_Shares[i].V) {
			log.Printf("[%v]Fail to recover share.", i)
		}
		simulateShare = append(simulateShare, myShare)
		log.Printf("[%v] Share is %v", i, myShare)
	}
	log.Printf("Success recover all share.\n\n")

	//**************************************
	//********This is for recover stage*****
	//***********Algorithm 2****************
	//**************************************
	log.Println("**************************************")
	log.Println("*************Start recover.***********")
	log.Println("**************************************")
	reRpoly, err := InterpolatePolynomial(g, simulateShare, thre_p, n)
	if err != nil {
		log.Printf("Fail to recover R poly.%v", err)
	}
	log.Printf("Recover poly R is %v", reRpoly)
	reSec, err := share.RecoverSecret(g, simulateShare, thre_p, n)
	if err != nil {
		log.Printf("Fail to recover secret.%v", err)
	}
	log.Printf("Recover secret is %v", reSec)
	log.Printf("Recover secret result:%v", reSec.Equal(secret))

	log.Println("**************************************")
	log.Println("************Succeed Verify.***********")
	log.Println("**************************************")
}
