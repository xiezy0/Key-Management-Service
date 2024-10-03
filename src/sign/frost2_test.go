package sign

import (
	"fmt"
	"testing"

	"hacss/src/cryptolib"

	"go.dedis.ch/kyber/v3"
	//"go.dedis.ch/kyber/v3/group/edwards25519"
)

func TestFrost2(test *testing.T) {

	//message
	m_ := "message"
	m := cryptolib.GenHash([]byte(m_))

	//dealer's secret s = f(0)
	s := cryptolib.GenSecret(group, rand)
	s_, _ := cryptolib.SerializeScalar(s)
	//dealer's private polynomial = f(x)
	pripoly := cryptolib.NewPriPoly(group, t, s, rand)

	//sks = f(i)
	sks := cryptolib.GenRPloyShares(pripoly, n)

	//generate the map used in lagrangeBasis
	var xs map[int]kyber.Scalar
	xs = make(map[int]kyber.Scalar)
	x, _ := xyScalar(group, sks, n, n)
	xs = x

	//compute the lagrange basis
	lag_basis := make([]kyber.Scalar, n)
	for i := 0; i < len(lag_basis); i++ {
		lag := lagrangeBasis(group, i, xs).coeffs
		lag_basis[i] = lag[0]
		//fmt.Printf("lagrange_basis_%d--%d", i, lag_basis[i])
		//fmt.Println(" ")
	}

	//X^ = g^f(0)
	x_hat := group.Point().Mul(s, g)

	/*test the lagrange basis
	x_test := group.Scalar().Zero()
	var sym []kyber.Scalar
	sym = make([]kyber.Scalar, n)

	for i := 0; i < n; i++ {
		sym[i] = group.Scalar().Mul(lag_basis[i], pripoly.Eval(i).V)
		fmt.Println("sym-------------", i, sym)
		fmt.Println(" ")
		x_test = group.Scalar().Add(x_test, sym[i])
		fmt.Println("test--", i, x_test)
		fmt.Println(" ")
	}*/

	fmt.Println("g--", g)
	fmt.Println(" ")
	fmt.Println("n--", n, "threshold--", t, "s--", s)
	fmt.Println("[]byte(s)--", s_)
	fmt.Println(" ")
	fmt.Println("X^--", x_hat)
	fmt.Println(" ")
	fmt.Println("message--", m)
	fmt.Println(" ")

	// Step1
	// test sign1
	// *******************
	//generate n private randomness
	var priRs = make([]PriRandomness, n)
	for i := 0; i < n; i++ {
		priRs[i] = Sign1(i)
		fmt.Println(" ")
		fmt.Printf("private randomness of player_%d--R:%d,S:%d", i, priRs[i].R_, priRs[i].S_)
		fmt.Println(" ")
	}

	//generate n public randomness
	var pubRs = make([]PubRandomness, n)
	for i := 0; i < n; i++ {
		pubRs[i] = priRs[i].Pub
		fmt.Println(" ")
		fmt.Printf("public randomness of player_%d--g^R:%d,g^S:%d", i, pubRs[i].R, pubRs[i].S)
		fmt.Println(" ")
	}

	// Step2
	// test sign2
	// *******************
	var sign2_outputs []sign2_output
	sign2_outputs = make([]sign2_output, n)

	for i := 0; i < n; i++ {
		sign2_outputs[i].r_hat, sign2_outputs[i].z = Sign2(t, priRs[i], sks[i].V, m, pubRs, x_hat, lag_basis[i])
		fmt.Println(" ")
		fmt.Printf("second round signature of player_%d--r_hat:%d,z:%d", i, sign2_outputs[i].r_hat, sign2_outputs[i].z)
		fmt.Println(" ")
	}

	// Step3
	// test combine
	// *******************
	var sign_slices []sign_slice
	sign_slices = make([]sign_slice, n)

	for i := 0; i < n; i++ {
		sign_slices[i].rho = pubRs[i]
		sign_slices[i].rho1 = sign2_outputs[i].z
		fmt.Println(" ")
		fmt.Printf("signature slice of player_%d--pubrandomnessR:%d,pubrandomnessS:%d,rho1:%d", i, sign_slices[i].rho.R, sign_slices[i].rho.S, sign_slices[i].rho1)
		fmt.Println(" ")
	}

	sigma_r_hat, sigma_z := Combine(m, sign_slices, x_hat)
	fmt.Println(" ")
	fmt.Printf("the combined signature (R^,z) is--R^:%d,z:%d", sigma_r_hat, sigma_z)
	fmt.Println(" ")

	// Step4
	// test verify_signature
	// *******************
	if Verify_signature(x_hat, m, sigma_r_hat, sigma_z) {
		fmt.Println("Verify_signature succeed!")
	} else {
		fmt.Println("Verify_signature failed!")
	}

	//test  hash_non
	//fmt.Println(H_non(selector_non, x_hat, m, pubRs))
	//test  hash_sig
	//fmt.Println(H_sig(selector_sig, x_hat, m, x_hat))
}
