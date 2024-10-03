package sign

import (
	"bytes"
	"fmt"
	"hacss/src/utils"
	"sort"

	"hacss/src/cryptolib"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"

	//"go.dedis.ch/kyber/v3/group/curve25519"
	"go.dedis.ch/kyber/v3/share"
)

// specify a group
var group = edwards25519.NewBlakeSHA256Ed25519()

//var group = curve25519.NewBlakeSHA256Curve25519(false)

// random point g
var rand = group.RandomStream()
var g = group.Point().Pick(rand)

// players
var n = 4

// threshold
var t = 2

// selectors of hash functions
var selector_non_ = "Selector of H_non"
var selector_non = []byte(selector_non_)
var selector_sig_ = "Selector of H_sig"
var selector_sig = []byte(selector_sig_)

type PriPoly struct {
	g      kyber.Group    // Cryptographic group
	coeffs []kyber.Scalar // Coefficients of the polynomial
}

// Threshold returns the secret sharing threshold.
func (p *PriPoly) Threshold() int {
	return len(p.coeffs)
}

// Eval computes the private share v = p(i)
func (p *PriPoly) Eval(i int) *share.PriShare {
	xi := p.g.Scalar().SetInt64(1 + int64(i))
	v := p.g.Scalar().Zero()
	for j := p.Threshold() - 1; j >= 0; j-- {
		v.Mul(v, xi)
		v.Add(v, p.coeffs[j])
	}
	return &share.PriShare{i, v}
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
		basis = basis.Mul(minusConst(g, xm)) // minusConst: -xm + x
		den.Sub(xs[i], xm)                   // den = xi - xm
		den.Inv(den)                         // den = 1 / den
		acc.Mul(acc, den)                    // acc = acc * den
	}

	// multiply all coefficients by the denominator
	for i := range basis.coeffs {
		basis.coeffs[i] = basis.coeffs[i].Mul(basis.coeffs[i], acc)
	}
	return basis // polynomial L_i(x)
}

type byIndexScalar []*share.PriShare

func (s byIndexScalar) Len() int           { return len(s) }
func (s byIndexScalar) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s byIndexScalar) Less(i, j int) bool { return s[i].I < s[j].I }

// xyScalar returns the list of (x_i, y_i) pairs indexed. The first map returned
// is the list of x_i and the second map is the list of y_i, both indexed in
// their respective map at index i.
func xyScalar(g kyber.Group, shares []*share.PriShare, t, n int) (map[int]kyber.Scalar, map[int]kyber.Scalar) {
	// we are sorting first the shares since the shares may be unrelated for
	// some applications. In this case, all participants needs to interpolate on
	// the exact same order shares.
	sorted := make([]*share.PriShare, 0, n)
	for _, share := range shares {
		if share != nil {
			sorted = append(sorted, share)
		}
	}
	sort.Sort(byIndexScalar(sorted))

	x := make(map[int]kyber.Scalar)
	y := make(map[int]kyber.Scalar)
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

// rho_k in the paper
type PubRandomness struct {
	I int
	R kyber.Point
	S kyber.Point
}

// st_k in the paper
type PriRandomness struct {
	R_  kyber.Scalar
	S_  kyber.Scalar
	Pub PubRandomness
}

// init a PriRandomness
func (a *PriRandomness) Init(i int) {
	a.R_ = group.Scalar().Pick(rand) //pick a random scalar r
	a.S_ = group.Scalar().Pick(rand) //pick a random scalar s
	a.Pub.I = i
	a.Pub.R = group.Point().Mul(a.R_, g) //R = g ^ r
	a.Pub.S = group.Point().Mul(a.S_, g) //S = g ^ s
}

type sign_slice struct {
	rho  PubRandomness
	rho1 kyber.Scalar
}

type sign2_output struct {
	r_hat kyber.Point
	z     kyber.Scalar
}

// hash function: H_non
func H_non(selector []byte, x_hat kyber.Point, m []byte, pubRs []PubRandomness) kyber.Scalar {
	var buffer bytes.Buffer
	buffer.Write(selector)
	x_hat_, _ := x_hat.MarshalBinary()
	buffer.Write(x_hat_)
	buffer.Write(m)
	for j := 0; j < len(pubRs); j++ {
		i_ := utils.IntToBytes(pubRs[j].I)
		r_, _ := pubRs[j].R.MarshalBinary()
		s_, _ := pubRs[j].S.MarshalBinary()
		buffer.Write(i_)
		buffer.Write(r_)
		buffer.Write(s_)
	}
	sym := buffer.Bytes()
	sym_ := cryptolib.GenHash(sym)

	var result_ = group.Scalar().Pick(rand)
	result, _ := cryptolib.DeserializeScalar(result_, sym_)
	return result
}

// hash function: H_sig
func H_sig(selector []byte, x_hat kyber.Point, m []byte, r_hat kyber.Point) kyber.Scalar {
	var buffer bytes.Buffer
	buffer.Write(selector)
	x_hat_, _ := x_hat.MarshalBinary()
	buffer.Write(x_hat_)
	buffer.Write(m)
	r_hat_, _ := r_hat.MarshalBinary()
	buffer.Write(r_hat_)

	sym := buffer.Bytes()
	sym_ := cryptolib.GenHash(sym)

	var result_ = group.Scalar().Pick(rand)
	result, _ := cryptolib.DeserializeScalar(result_, sym_)
	return result
}

// judge that whether there are identical elements in a []PubRandomness or not
func findDuplicates(a []PubRandomness) bool {
	var mapper map[PubRandomness]int
	mapper = make(map[PubRandomness]int)
	var i int
	for i = 0; i < len(a); i++ {
		mapper[a[i]]++
	}
	var flag = false
	for _, value := range mapper {
		if value >= 2 {
			flag = true
		} else {
			flag = false
		}
	}
	return flag
}

// first round of signing
func Sign1(i int) PriRandomness {
	var priR PriRandomness
	priR.Init(i)
	return priR
}

// second round of signing
func Sign2(k int, priR PriRandomness, sk kyber.Scalar, m []byte, pubRs []PubRandomness, x_hat kyber.Point, lag_basis kyber.Scalar) (kyber.Point, kyber.Scalar) {
	var stk1 = group.Point().Pick(rand)
	var rhok1 = group.Scalar().Pick(rand)
	if len(pubRs) >= t {
		if findDuplicates(pubRs) {
			fmt.Println("there are identical elements in the set of public randomness!")
			return stk1, rhok1
		} else {
			a := H_non(selector_non, x_hat, m, pubRs)

			var r_hat = group.Point().Add(pubRs[0].R, group.Point().Mul(a, pubRs[0].S)) // init R^ = R_0 * S_0^a

			for i := 1; i < len(pubRs); i++ {
				r_hat = group.Point().Add(r_hat, group.Point().Add(pubRs[i].R, group.Point().Mul(a, pubRs[i].S))) // R^ = R^ * R_i * S_i^a
				//fmt.Printf("%d:test r_hat:%d", i, r_hat)
				//fmt.Println(" ")
			}
			c := H_sig(selector_sig, x_hat, m, r_hat)
			z1 := group.Scalar().Add(priR.R_, group.Scalar().Mul(a, priR.S_)) // z1 = r + a*s
			z2 := group.Scalar().Mul(group.Scalar().Mul(c, lag_basis), sk)    // z2 = c * lag_basis * sk
			z := group.Scalar().Add(z1, z2)                                   // z = z1 + z2

			stk1 = r_hat
			rhok1 = z
			return stk1, rhok1
		}
	} else {
		fmt.Println("the amount of public randomness is lower than threshold!")
		return stk1, rhok1
	}
}

func Combine(m []byte, sign_slices []sign_slice, x_hat kyber.Point) (kyber.Point, kyber.Scalar) {
	var r_hat_ = group.Point().Base()
	var z = group.Scalar().Zero()
	if len(sign_slices) >= t {
		var sym []PubRandomness
		sym = make([]PubRandomness, len(sign_slices))
		for i := range sign_slices {
			sym[i] = sign_slices[i].rho
		}
		a := H_non(selector_non, x_hat, m, sym)
		r_hat_ = group.Point().Add(sym[0].R, group.Point().Mul(a, sym[0].S)) // init R^ = R_0 * S_0^a
		for i := 1; i < len(sym); i++ {
			r_hat_ = group.Point().Add(r_hat_, group.Point().Add(sym[i].R, group.Point().Mul(a, sym[i].S))) // R^ = R^ * R_i * S_i^a
		}
		//z = sum all the rho1s
		var z = group.Scalar().Zero()
		for i := range sign_slices {
			z = group.Scalar().Add(z, sign_slices[i].rho1)
		}
		return r_hat_, z
	} else {
		fmt.Println("the amount of signature slices is lower than threshold!")
		return r_hat_, z
	}
}

func Verify_signature(x_hat kyber.Point, m []byte, r_hat kyber.Point, z kyber.Scalar) bool {
	c := H_sig(selector_sig, x_hat, m, r_hat)
	left := group.Point().Add(r_hat, group.Point().Mul(c, x_hat)) //left = R^ * (X^)^c
	right := group.Point().Mul(z, g)                              // right = g^z
	if left.Equal(right) {
		return true
	} else {
		return false
	}
}
