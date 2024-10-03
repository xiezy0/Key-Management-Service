package encryption_TDH2

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"sort"

	"hacss/src/cryptolib"

	"go.dedis.ch/kyber/v3"
	//"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

var group = edwards25519.NewBlakeSHA256Ed25519()
var rand = group.RandomStream()
var g = group.Point().Pick(rand)  //random point g
var g1 = group.Point().Pick(rand) //random point g1
// var zero = group.Point().zero
// var one = group.Point().one
var players = 4
var k = 2

// H_1
func HashG(g kyber.Point) []byte {
	g_, _ := g.MarshalBinary()
	return cryptolib.GenHash(g_)
}

// H_2
func HashH(c []byte, l []byte, u kyber.Point, w kyber.Point, u1 kyber.Point, w1 kyber.Point) kyber.Scalar {
	u_, _ := u.MarshalBinary()
	w_, _ := w.MarshalBinary()
	u1_, _ := u1.MarshalBinary()
	w1_, _ := w1.MarshalBinary()

	var buffer bytes.Buffer
	buffer.Write(c)
	buffer.Write(l)
	buffer.Write(u_)
	buffer.Write(w_)
	buffer.Write(u1_)
	buffer.Write(w1_)
	sym := buffer.Bytes()

	sym_ := cryptolib.GenHash(sym)

	var result_ = group.Scalar().Pick(rand)
	result, _ := cryptolib.DeserializeScalar(result_, sym_)
	return result

}

// H_4
func Hash4(u kyber.Point, u1 kyber.Point, h1 kyber.Point) kyber.Scalar {
	u_, _ := u.MarshalBinary()
	u1_, _ := u1.MarshalBinary()
	h1_, _ := h1.MarshalBinary()

	var buffer bytes.Buffer
	buffer.Write(u_)
	buffer.Write(u1_)
	buffer.Write(h1_)
	sym := buffer.Bytes()

	sym_ := cryptolib.GenHash(sym)

	var result_ = group.Scalar().Pick(rand)
	result, _ := cryptolib.DeserializeScalar(result_, sym_)
	return result
}

type PriPoly struct {
	g      kyber.Group    // Cryptographic group
	coeffs []kyber.Scalar // Coefficients of the polynomial
}

func minusConst(g kyber.Group, c kyber.Scalar) *PriPoly {
	neg := g.Scalar().Neg(c)
	return &PriPoly{
		g:      g,
		coeffs: []kyber.Scalar{neg, g.Scalar().One()},
	}
}

// Mul multiples p and q together. The result is a polynomial of the sum of
// the two degrees of p and q. NOTE: it does not check for null coefficients
// after the multiplication, so the degree of the polynomial is "always" as
// described above. This is only for use in secret sharing schemes. It is not
// a general polynomial multiplication routine.
func (p *PriPoly) Mul(q *PriPoly) *PriPoly {
	d1 := len(p.coeffs) - 1
	d2 := len(q.coeffs) - 1
	newDegree := d1 + d2
	coeffs := make([]kyber.Scalar, newDegree+1)
	for i := range coeffs {
		coeffs[i] = p.g.Scalar().Zero()
	}
	for i := range p.coeffs {
		for j := range q.coeffs {
			tmp := p.g.Scalar().Mul(p.coeffs[i], q.coeffs[j])
			coeffs[i+j] = tmp.Add(coeffs[i+j], tmp)
		}
	}
	return &PriPoly{p.g, coeffs}
}

// lagrangeBasis returns a PriPoly containing the Lagrange coefficients for the
// i-th position. xs is a mapping between the indices and the values that the
// interpolation is using, computed with xyScalar().
func lagrangeBasis(g kyber.Group, i int, xs map[int]kyber.Scalar) *PriPoly {
	var basis = &PriPoly{
		g:      g,
		coeffs: []kyber.Scalar{g.Scalar().One()},
	}
	// compute lagrange basis l_j
	den := g.Scalar().One()
	var acc = g.Scalar().One()
	for m, xm := range xs {
		if i == m {
			continue
		}
		basis = basis.Mul(minusConst(g, xm))
		den.Sub(xs[i], xm) // den = xi - xm
		den.Inv(den)       // den = 1 / den
		acc.Mul(acc, den)  // acc = acc * den
	}

	// multiply all coefficients by the denominator
	for i := range basis.coeffs {
		basis.coeffs[i] = basis.coeffs[i].Mul(basis.coeffs[i], acc)
	}
	return basis
}

// PubShare represents a public share.
type PubShare struct {
	I int         // Index of the public share
	V kyber.Point // Value of the public share
}

type byIndexPub []*PubShare

func (s byIndexPub) Len() int           { return len(s) }
func (s byIndexPub) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s byIndexPub) Less(i, j int) bool { return s[i].I < s[j].I }

// xyCommits is the public version of xScalars.
func xyCommit(g kyber.Group, shares []*PubShare, t, n int) (map[int]kyber.Scalar, map[int]kyber.Point) {
	// we are sorting first the shares since the shares may be unrelated for
	// some applications. In this case, all participants needs to interpolate on
	// the exact same order shares.
	sorted := make([]*PubShare, 0, n)
	for _, share := range shares {
		if share != nil {
			sorted = append(sorted, share)
		}
	}
	sort.Sort(byIndexPub(sorted))

	x := make(map[int]kyber.Scalar)
	y := make(map[int]kyber.Point)

	for _, s := range sorted {
		if s == nil || s.V == nil || s.I < 0 {
			continue
		}
		idx := s.I
		x[idx] = g.Scalar().SetInt64(int64(idx + 1))
		y[idx] = s.V
		if len(x) == t {
			break
		}
	}
	return x, y
}

// RecoverCommit reconstructs the secret commitment p(0) from a list of public
// shares using Lagrange interpolation.
func RecoverCommit(g kyber.Group, shares []*PubShare, t, n int) (kyber.Point, error) {
	x, y := xyCommit(g, shares, t, n)
	if len(x) < t {
		return nil, errors.New("share: not enough good public shares to reconstruct secret commitment")
	}

	num := g.Scalar()
	den := g.Scalar()
	tmp := g.Scalar()
	Acc := g.Point().Null()
	Tmp := g.Point()

	for i, xi := range x {
		num.One()
		den.One()
		for j, xj := range x {
			if i == j {
				continue
			}
			num.Mul(num, xj)
			den.Mul(den, tmp.Sub(xj, xi))
		}
		Tmp.Mul(num.Div(num, den), y[i])
		Acc.Add(Acc, Tmp)
	}

	return Acc, nil
}

// n -- number of players
// k -- threshold
// VK -- verification key
// VKs -- verification keys
type TDHPublicKey struct {
	N   int
	K   int
	VK  kyber.Point
	VKs []kyber.Point
}

func (a *TDHPublicKey) Init(n int, k int, vk kyber.Point, vks []kyber.Point) {
	a.N = n
	a.K = k
	a.VK = vk
	a.VKs = vks
}

// TBD: the length of the input
func (a *TDHPublicKey) Encrypt(m []byte, l []byte, rand cipher.Stream) ([]byte, []byte, kyber.Point, kyber.Point, kyber.Scalar, kyber.Scalar) {
	var c = make([]byte, 32)
	//var u = group.Point().Pick(rand)
	//var u1 = group.Point().Pick(rand)
	//var e = group.Scalar().Pick(rand)
	//var f = group.Scalar().Pick(rand)
	var u kyber.Point
	var u1 kyber.Point
	var e kyber.Scalar
	var f kyber.Scalar

	if len(m) == 32 {
		r := group.Scalar().Pick(rand) //random r
		s := group.Scalar().Pick(rand) //random s

		//c = H_1(a.VK^r xor m)
		var c_ byte
		for i := 0; i < 32; i++ {
			c_ = HashG(group.Point().Mul(r, a.VK))[i] ^ m[i]
			c[i] = c_
		}

		u := group.Point().Mul(r, g) //u = g^r
		//fmt.Println(" ")
		//fmt.Println("u in Encrypt:", u)
		//fmt.Println(" ")
		w := group.Point().Mul(s, g) //w = g^s
		//fmt.Println(" ")
		//fmt.Println("w in Encrypt:", w)
		//fmt.Println(" ")
		u1 = group.Point().Mul(r, g1) //u1 = g^r
		//fmt.Println(" ")
		//fmt.Println("u1 in Encrypt:", u1)
		//fmt.Println(" ")
		w1 := group.Point().Mul(s, g1) //u1 = g^s
		//fmt.Println(" ")
		//fmt.Println("w1 in Encrypt:", w1)
		//fmt.Println(" ")
		e = HashH(c, l, u, w, u1, w1)
		//fmt.Println(" ")
		//fmt.Println("e in Encrypt:", e)
		//fmt.Println(" ")
		f = group.Scalar().Add(s, group.Scalar().Mul(r, e)) //f = s + r*e
		//g_f := group.Point().Mul(f, g)
		//fmt.Println(" ")
		//fmt.Println("g^f in Encrypt:", g_f)
		//fmt.Println(" ")
		//u_e := group.Point().Mul(e, u)
		//fmt.Println(" ")
		//fmt.Println("u^e in Encrypt:", u_e)
		//fmt.Println(" ")
		return c, l, u, u1, e, f
	} else {
		fmt.Println("the length of 'm' is not 32 bytes(256 bits)!")
		return c, l, u, u1, e, f
	}
}

func (a *TDHPublicKey) Verify_ciphertext(c []byte, l []byte, u kyber.Point, u1 kyber.Point, e kyber.Scalar, f kyber.Scalar) bool {
	//g_f := group.Point().Mul(f, g)
	//fmt.Println(" ")
	//fmt.Println("g_f in Verify_ciphertext:", g_f)
	//fmt.Println(" ")
	//u_e := group.Point().Mul(e, u)
	//fmt.Println(" ")
	//fmt.Println("u^e in Verify_ciphertext:", u_e)
	//fmt.Println(" ")
	w := group.Point().Sub(group.Point().Mul(f, g), group.Point().Mul(e, u)) //w = g^f/u^e
	//fmt.Println(" ")
	//fmt.Println("w in Verify_ciphertext:", w)
	//fmt.Println(" ")
	w1 := group.Point().Sub(group.Point().Mul(f, g1), group.Point().Mul(e, u1)) //w1 = g1^f/u1^e
	//fmt.Println(" ")
	//fmt.Println("w1 in Verify_ciphertext:", w1)
	//fmt.Println(" ")
	H := HashH(c, l, u, w, u1, w1)
	//fmt.Println(" ")
	//fmt.Println("H in Verify_ciphertext:", H)
	//fmt.Println(" ")
	//fmt.Println(" ")
	//fmt.Println("e in Verify_ciphertext:", e)
	//fmt.Println(" ")
	if e.Equal(H) {
		return true
	} else {
		return false
	}
}

// Verify_share , which takes the index i, share_i(i.e. u_i,e_i,f_i)
// and ciphertext as inputs,
// and will judge whether the share is well-formed or not,
// is the method of TDHPublicKey
func (a *TDHPublicKey) Verify_share(i int, u_i kyber.Point, e_i kyber.Scalar, f_i kyber.Scalar, c []byte, l []byte, u kyber.Point, u1 kyber.Point, e kyber.Scalar, f kyber.Scalar) bool {
	if (0 <= i) && (i < a.N) {
		h_i := a.VKs[i]
		u1_i := group.Point().Sub(group.Point().Mul(f_i, u), group.Point().Mul(e_i, u_i)) //u1_i = u^f_i/u_i^e_i
		h1_i := group.Point().Sub(group.Point().Mul(f_i, g), group.Point().Mul(e_i, h_i)) //h1_i = g^f_i/h_i^e_i
		h_result := Hash4(u_i, u1_i, h1_i)
		if e_i.Equal(h_result) {
			//fmt.Printf("player_%d verify_share succeed!", i)
			//fmt.Println(" ")
			return true
		} else {
			//fmt.Printf("player_%d verify_share failed!", i)
			//fmt.Println(" ")
			return false
		}
	} else {
		fmt.Println("wrong parameters!")
		return false
	}
}

// Combine_shares takes the ciphertext and public shares
// of participants as inputs,
// to output the decrypted text m
func (a *TDHPublicKey) Combine_shares(c []byte, l []byte, u kyber.Point, u1 kyber.Point, e kyber.Scalar, f kyber.Scalar, pub_shares []*PubShare) []byte {
	//guarantee that the amount of shares is larger than threshold
	var m_ byte
	var m []byte
	if len(pub_shares) >= a.K {
		res, _ := RecoverCommit(group, pub_shares, a.K, a.N) //res = h^r, which is recovered from the shares by lagerange interpolation
		res_ := HashG(res)
		//m = H_1(res xor c)
		for i := 0; i < 32; i++ {
			m_ = res_[i] ^ c[i]
			m = append(m, m_)
		}
		return m
	} else {
		fmt.Println("the amount of shares is lower than threshold!")
		return m
	}
}

// SK -- private keys
// SK_i -- the i-th private key
type TDHPrivateKey struct {
	PK TDHPublicKey
	I  int
	SK kyber.Scalar
}

func (a *TDHPrivateKey) Init(p *TDHPublicKey, i int, sk kyber.Scalar) {
	a.PK = *p
	a.I = i
	a.SK = sk
}

// Decrypt_share, which takes the ciphertext as inputs,
// and will output u_i, e_i, f_i as the decryption share of player_i,
// is the method of TDHPublicKey
func (a *TDHPrivateKey) Decrypt_share(c []byte, l []byte, u kyber.Point, u1 kyber.Point, e kyber.Scalar, f kyber.Scalar, rand cipher.Stream) (kyber.Point, kyber.Scalar, kyber.Scalar) {
	u_i := group.Point().Mul(a.SK, u) //u_i = u^a.SK
	si := group.Scalar().Pick(rand)   //random si
	u1_i := group.Point().Mul(si, u)  //u1_i = u^si
	h1_i := group.Point().Mul(si, g)  //h1_i = g^si
	e_i := Hash4(u_i, u1_i, h1_i)
	f_i := group.Scalar().Add(si, group.Scalar().Mul(a.SK, e_i)) //f_i = si + a.SK*e_i
	return u_i, e_i, f_i
}

type dec_share struct {
	u_i kyber.Point
	e_i kyber.Scalar
	f_i kyber.Scalar
}
