package encryption_TDH2

import (
	"bytes"
	"fmt"
	"testing"

	"hacss/src/cryptolib"

	"go.dedis.ch/kyber/v3"
	//"go.dedis.ch/kyber/v3/group/edwards25519"
	//"go.dedis.ch/kyber/v3/share"
)

func TestEncryption(test *testing.T) {
	//total number of players
	n := players
	//recovery threshold
	p := k
	//message
	m_ := "message"
	m := cryptolib.GenHash([]byte(m_))
	//m__ := cryptolib.GenHash([]byte(m_))
	//m := string(m__)
	//label
	l_ := "label"
	l := cryptolib.GenHash([]byte(l_))
	//l__ := cryptolib.GenHash([]byte(l_))
	//l := string(l__)
	//dealer's secret s = f(0)
	s := cryptolib.GenSecret(group, rand)
	//dealer's private polynomial = f(x)
	pripoly := cryptolib.NewPriPoly(group, k, s, rand)
	//sks = f(i)
	sks := cryptolib.GenRPloyShares(pripoly, n)
	//vks = g^f(i)
	var vks = make([]kyber.Point, n)
	for i := 0; i < n; i++ {
		vks[i] = group.Point().Mul(sks[i].V, g)
	}
	//vk = g^f(0)
	vk := group.Point().Mul(s, g)
	//PK
	var pk TDHPublicKey
	pk.Init(n, k, vk, vks)

	fmt.Println("g--", g, "n--", n, "p--", p, "s--", s)
	fmt.Println(" ")
	fmt.Println("message--", m)
	fmt.Println("label--", l)
	fmt.Println(" ")
	for i := 0; i < n; i++ {
		fmt.Printf("SK_%d--", sks[i].V)
		fmt.Println(" ")
	}
	fmt.Println("PK--", pk)
	fmt.Println("VKs--", vks)
	fmt.Println("VK--", vk)
	fmt.Println(" ")

	//separate sks to sk
	var sk = make([]TDHPrivateKey, n)
	for i := 0; i < n; i++ {
		sk[i].Init(&pk, i, sks[i].V)
		fmt.Printf("SK_%d--%d", i, sk[i].SK)
		fmt.Println(" ")
	}

	// Step 1
	// encrypt the message
	// *******************
	c, L, u, u1, e, f := pk.Encrypt(m, l, rand)
	fmt.Println("ciphertext: ", "c--", c, "L--", L, "u--", u, "u1--", u1, "e--", e, "f--", f)
	fmt.Println(" ")

	// Step2
	// verify the ciphertext C
	// *******************
	/*if pk.Verify_ciphertext(c, L, u, u1, e, f) {
		fmt.Println("Verify_ciphertext succeed!")
		fmt.Println(" ")
	} else {
		fmt.Println("Verify_ciphertext failed!")
		fmt.Println(" ")
	}*/

	// Step3
	// generate decryption shares
	// *******************
	var shares []dec_share
	shares = make([]dec_share, n)
	for i := 0; i < n; i++ {
		shares[i].u_i, shares[i].e_i, shares[i].f_i = sk[i].Decrypt_share(c, L, u, u1, e, f, rand)
		fmt.Println(" ")
		fmt.Printf("decrypt_share of player_%d is--", i)
		fmt.Println(" ")
		fmt.Printf("u_%d--%d", i, shares[i].u_i)
		fmt.Println(" ")
		fmt.Printf("e_%d--%d", i, shares[i].e_i)
		fmt.Println(" ")
		fmt.Printf("f_%d--%d", i, shares[i].f_i)
		fmt.Println(" ")
	}

	// Step4
	// verify the shares
	// *******************
	for i := 0; i < n; i++ {
		pk.Verify_share(i, shares[i].u_i, shares[i].e_i, shares[i].f_i, c, L, u, u1, e, f)
	}

	// Step5
	// combine the shares
	// *******************
	var ss = make([]*PubShare, n)
	for i := 0; i < k; i++ {
		ss[i] = &PubShare{i, shares[i].u_i}
	}
	mm := pk.Combine_shares(c, L, u, u1, e, f, ss)
	if bytes.Equal(mm, m) {
		fmt.Println("combine succeed!")
	} else {
		fmt.Println("combine failed!")
	}

}
