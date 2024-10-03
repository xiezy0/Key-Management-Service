package hacss

import (
	"bytes"
	"crypto/cipher"
	"go.dedis.ch/kyber/v3/share"
	"hacss/src/cryptolib"
	"log"

	"go.dedis.ch/kyber/v3"
)

/*
GenerateRandSecret : Generate a random secret.
*/
func GenerateRandSecret(group kyber.Group, rand cipher.Stream) kyber.Scalar {

	return cryptolib.GenSecret(group, rand)
}

/*
GenerateRandPolynomial : Generate a random polynomial using Kyber lib.
*/
func GenerateRandPolynomial(group kyber.Group, thre_p int, s kyber.Scalar, rand cipher.Stream) Polynomial {

	return cryptolib.GenRPloy(group, thre_p, s, rand)
}

/*
GeneratePolyCommitment : Compute exponent result for generator "g" using the coefficient of the polynomial.
*/
func GeneratePolyCommitment(poly Polynomial) cryptolib.PubPoly {

	return *cryptolib.GenRPloyCommitment(poly)
}

/*
Multiply point p by the scalar s.
if p == nil, multiply with the standard base point Base().
*/
func ComputeExponent(s kyber.Scalar, group kyber.Group) kyber.Point {

	return group.Point().Mul(s, nil)
}

/*
ComputePolyValue : compute the result for a given polynomial "p" and a variable "x", i.e. p(x).
*/
func ComputePolyValue(p Polynomial, n int) PolyResult {
	// todo: provide a method to compute p(n)
	return cryptolib.GenRPloyShares(p, n)[n-1]
}

/*
GenerateVectorCommitment : compute the merkle tree of the input "data".
return: merkel tree root, merkle branches, index of each element, if success bool is true.
*/
func GenerateVectorCommitment(data [][]byte) ([]byte, [][][]byte, [][]int64, bool) {
	C := cryptolib.GenMerkleTreeRoot(data)
	branches, idxResult := cryptolib.ObtainMerklePath(data)
	if len(branches) != len(data) || len(branches) != len(idxResult) {
		log.Println("Fail to get merkle branch when start HACSS!")
		return nil, nil, nil, false
	}
	return C, branches, idxResult, true
}

/*
VerifyMerkleRoot input: frag is the original leaf data before hash;

	       branch is the branch of the leaf in the merkle tree;
	       index is the index of the branch element in the merkle tree;
		   root is the merkle tree root.
*/
func VerifyMerkleRoot(frag []byte, branch [][]byte, index []int64, root []byte) bool {
	hash := cryptolib.ObtainMerkleNodeHash(frag)
	for i := 0; i < len(index); i++ {
		if index[i]%2 == 0 { //leftnode
			chash := append(branch[i], hash...)
			hash = cryptolib.ObtainMerkleNodeHash(chash)
		} else {
			chash := append(hash, branch[i]...)
			hash = cryptolib.ObtainMerkleNodeHash(chash)
		}
	}

	return bytes.Compare(root, hash) == 0
}

/*
InterpolatePolynomial Recover the polynomial using Lagrange's interpolation
*/
func InterpolatePolynomial(g kyber.Group, shares []*share.PriShare, t, n int) (*cryptolib.PriPoly, error) {
	//var p Polynomial
	//todo: recover the poly
	return cryptolib.RecoverPriPoly(g, shares, t, n)

}
