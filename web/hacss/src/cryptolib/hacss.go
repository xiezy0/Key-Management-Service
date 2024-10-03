package cryptolib

import (
	"bytes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"sort"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
)

type PriPoly struct {
	g      kyber.Group    // Cryptographic group
	coeffs []kyber.Scalar // Coefficients of the polynomial
}

// NewPriPoly creates a new secret sharing polynomial using the provided
// cryptographic group, the secret sharing threshold t, and the secret to be
// shared s. If s is nil, a new s is chosen using the provided randomness
// stream rand.
func NewPriPoly(group kyber.Group, t int, s kyber.Scalar, rand cipher.Stream) *PriPoly {
	coeffs := make([]kyber.Scalar, t)
	coeffs[0] = s
	if coeffs[0] == nil {
		coeffs[0] = group.Scalar().Pick(rand)
	}
	for i := 1; i < t; i++ {
		coeffs[i] = group.Scalar().Pick(rand)
	}
	return &PriPoly{g: group, coeffs: coeffs}
}

// Commit creates a public commitment polynomial for the given base point B or
// the standard base if B == nil.
func (p *PriPoly) Commit(b kyber.Point) *PubPoly {
	commits := make([]kyber.Point, p.Threshold())
	for i := range commits {
		commits[i] = p.g.Point().Mul(p.coeffs[i], b)
	}
	return &PubPoly{p.g, b, commits}
}

// PubPoly represents a public commitment polynomial to a secret sharing polynomial.
type PubPoly struct {
	G       kyber.Group   // Cryptographic group
	B       kyber.Point   // Base point, nil for standard base
	Commits []kyber.Point // Commitments to coefficients of the secret sharing polynomial
}

type PubPolyBytes struct {
	G       string   // Cryptographic group
	B       []byte   // Base point, nil for standard base
	Commits [][]byte // Commitments to coefficients of the secret sharing polynomial
}

// PriShare represents a private share.
type PriShareBytes struct {
	I int    // Index of the private share
	V []byte // Value of the private share
}

func SerilizePriShare(p *share.PriShare) ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	serilized_v, _ := SerializeScalar(p.V)
	share := &PriShareBytes{
		I: p.I,
		V: serilized_v,
	}
	json_PriShare, err := json.Marshal(share)

	if err != nil {
		return []byte(""), err
	}
	return json_PriShare, nil
}

func DeserializePriShare(scalar kyber.Scalar, prisharebytes []byte) *share.PriShare {
	if prisharebytes == nil || bytes.Equal(prisharebytes, []byte("")) {
		return nil
	}
	var priShareBytes = new(PriShareBytes)
	var prishare = new(share.PriShare)
	err := json.Unmarshal(prisharebytes, &priShareBytes)
	if err == nil {
		serilized_V, _ := DeserializeScalar(scalar, priShareBytes.V)
		prishare = &share.PriShare{
			I: priShareBytes.I,
			V: serilized_V,
		}
		return prishare
	}
	return prishare
}

func (p *PubPoly) SerializePubPoly() ([]byte, error) {
	var B_serilize []byte
	var err error
	if p.B != nil {
		B_serilize, err = SerilizePoint(p.B)
		if err != nil {
			return nil, err
		}
	}
	Commit_temp := make([][]byte, 0)

	for i := 0; i < len(p.Commits); i++ {
		serilize_temp, _ := SerilizePoint(p.Commits[i])
		Commit_temp = append(Commit_temp, serilize_temp)
	}
	pub := &PubPolyBytes{
		G:       Suite.String(),
		B:       B_serilize,
		Commits: Commit_temp,
	}
	json_PubPoly, err := json.Marshal(pub)

	if err != nil {
		return []byte(""), err
	}
	return json_PubPoly, nil
}

func DeserilizePubPoly(pubBytes []byte) PubPoly {
	var pubPolyBytes = new(PubPolyBytes)
	var pubPoly = new(PubPoly)
	err := json.Unmarshal(pubBytes, &pubPolyBytes)
	if err == nil {
		var B_deserilize kyber.Point
		if pubPolyBytes.B != nil {
			B_deserilize, _ = DeserializePoint(Suite.Point(), pubPolyBytes.B)
		} else {
			B_deserilize = nil
		}
		Commit_temp := make([]kyber.Point, 0)
		for i := 0; i < len(pubPolyBytes.Commits); i++ {
			deserilize_temp, _ := DeserializePoint(Suite.Point(), pubPolyBytes.Commits[i])
			Commit_temp = append(Commit_temp, deserilize_temp)
		}

		pubPoly = &PubPoly{
			G:       Suite,
			B:       B_deserilize,
			Commits: Commit_temp,
		}
		return *pubPoly
	}

	return *pubPoly

}

// Threshold returns the secret sharing threshold.
func (p *PriPoly) Threshold() int {
	return len(p.coeffs)
}

// Shares creates a list of n private shares p(1),...,p(n).
func (p *PriPoly) Shares(n int) []*share.PriShare {
	shares := make([]*share.PriShare, n)
	for i := range shares {
		shares[i] = p.Eval(i)
	}
	return shares
}

// Eval computes the private share v = p(i).
func (p *PriPoly) Eval(i int) *share.PriShare {
	xi := p.g.Scalar().SetInt64(1 + int64(i))
	v := p.g.Scalar().Zero()
	for j := p.Threshold() - 1; j >= 0; j-- {
		v.Mul(v, xi)
		v.Add(v, p.coeffs[j])
	}
	return &share.PriShare{i, v}
}

func GenRPloy(group kyber.Group, thre_p int, s kyber.Scalar, rand cipher.Stream) *PriPoly {
	return NewPriPoly(group, thre_p, s, rand)
}

func GenSecret(group kyber.Group, rand cipher.Stream) kyber.Scalar {
	secret := group.Scalar().Pick(rand)
	return secret
}

func GenRPloyCommitment(R_Ploy *PriPoly) *PubPoly {
	return R_Ploy.Commit(nil)
}

func GenRPloyShares(R_Ploy *PriPoly, n int) []*share.PriShare {
	return R_Ploy.Shares(n)
}

func GenSSharePoly(t int, n int, group kyber.Group, rand cipher.Stream, R_Poly_shares []*share.PriShare) []*PriPoly {
	S_Share_Poly := make([]*PriPoly, n)
	for i := 0; i < n; i++ {
		S_Share_Poly[i] = GenSSharePolySwithR(group, t, rand, i+1, R_Poly_shares[i])
	}
	return S_Share_Poly
}

func GenSSharePolySwithR(group kyber.Group, t int, rand cipher.Stream, i int, r_j *share.PriShare) *PriPoly {
	coeffs := make([]kyber.Scalar, t+1)
	xi := group.Scalar().SetInt64(int64(i))
	x := group.Scalar().Zero()
	for i := 0; i <= t; i++ {
		if i == 0 {
			coeffs[0] = group.Scalar().Zero()
		} else {
			coeffs[i] = group.Scalar().Pick(rand)
		}

	}
	for j := t; j >= 0; j-- {
		x.Mul(x, xi)
		x.Add(x, coeffs[j])
	}
	coeffs[0] = group.Scalar().Sub(r_j.V, x)

	return &PriPoly{g: group, coeffs: coeffs}
}

func GenSSharePolyCommitment(S_Poly []*PriPoly, n int) []*PubPoly {
	S_Poly_Commitment := make([]*PubPoly, n)
	for i := 0; i < n; i++ {
		S_Poly_Commitment[i] = S_Poly[i].Commit(nil)
	}
	return S_Poly_Commitment
}

func GenSSharePolyShares(S_Poly []*PriPoly, n int) [][]*share.PriShare {
	S_Share_Poly_Shares := make([][]*share.PriShare, 0)
	for i := 0; i < n; i++ {
		S_Share_Poly_Shares = append(S_Share_Poly_Shares, S_Poly[i].Shares(n))
	}
	return S_Share_Poly_Shares
}

// Shares creates a list of n public commitment shares p(1),...,p(n).
func (p *PubPoly) Shares(n int) []*share.PubShare {
	shares := make([]*share.PubShare, n)
	for i := range shares {
		shares[i] = p.Eval(i)
	}
	return shares
}

// Threshold returns the secret sharing threshold.
func (p *PubPoly) Threshold() int {
	return len(p.Commits)
}

// Serialize returns the byte type of PubPoly
//func (p *PubPoly) Serialize() ([]byte, error) {
//	//todo: maybe serialize with kyber lib, need be verified
//	jsons, err := json.Marshal(p)
//	if err != nil {
//		return []byte(""), err
//	}
//	return jsons, nil
//}

// Eval computes the public share v = p(i).
func (p *PubPoly) Eval(i int) *share.PubShare {
	xi := p.G.Scalar().SetInt64(1 + int64(i)) // x-coordinate of this share
	v := p.G.Point().Null()
	for j := p.Threshold() - 1; j >= 0; j-- {
		v.Mul(xi, v)
		v.Add(v, p.Commits[j])
	}
	return &share.PubShare{i, v}
}

func GenRPolyPubShares(R_Ploy_Commitment *PubPoly, n int) []*share.PubShare {
	return R_Ploy_Commitment.Shares(n)
}

func GenSSharePolyPubShares(S_Poly_Commitment []*PubPoly, n int) [][]*share.PubShare {
	S_Share_Poly_Pub_Shares := make([][]*share.PubShare, 0)
	for i := 0; i < n; i++ {
		S_Share_Poly_Pub_Shares = append(S_Share_Poly_Pub_Shares, S_Poly_Commitment[i].Shares(n))
	}
	return S_Share_Poly_Pub_Shares
}

// RecoverPriPoly takes a list of shares and the parameters t and n to
// reconstruct the secret polynomial completely, i.e., all private
// coefficients.  It is up to the caller to make sure that there are enough
// shares to correctly re-construct the polynomial. There must be at least t
// shares.
func RecoverPriPoly(g kyber.Group, shares []*share.PriShare, t, n int) (*PriPoly, error) {
	x, y := xyScalar(g, shares, t, n)
	if len(x) != t {
		return nil, errors.New("share: not enough shares to recover private polynomial")
	}

	var accPoly *PriPoly
	var err error
	//den := G.Scalar()
	// Notations follow the Wikipedia article on Lagrange interpolation
	// https://en.wikipedia.org/wiki/Lagrange_polynomial
	for j := range x {
		basis := lagrangeBasis(g, j, x)
		for i := range basis.coeffs {
			basis.coeffs[i] = basis.coeffs[i].Mul(basis.coeffs[i], y[j])
		}

		if accPoly == nil {
			accPoly = basis
			continue
		}

		// add all L_j * y_j together
		accPoly, err = accPoly.Add(basis)
		if err != nil {
			return nil, err
		}
	}
	return accPoly, nil
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

func minusConst(g kyber.Group, c kyber.Scalar) *PriPoly {
	neg := g.Scalar().Neg(c)
	return &PriPoly{
		g:      g,
		coeffs: []kyber.Scalar{neg, g.Scalar().One()},
	}
}

// Some error definitions
var errorGroups = errors.New("non-matching groups")
var errorCoeffs = errors.New("different number of coefficients")

// Add computes the component-wise sum of the polynomials p and q and returns it
// as a new polynomial.
func (p *PriPoly) Add(q *PriPoly) (*PriPoly, error) {
	if p.g.String() != q.g.String() {
		return nil, errorGroups
	}
	if p.Threshold() != q.Threshold() {
		return nil, errorCoeffs
	}
	coeffs := make([]kyber.Scalar, p.Threshold())
	for i := range coeffs {
		coeffs[i] = p.g.Scalar().Add(p.coeffs[i], q.coeffs[i])
	}
	return &PriPoly{p.g, coeffs}, nil
}

// Secret returns the shared secret p(0), i.e., the constant term of the polynomial.
func (p *PriPoly) Secret() kyber.Scalar {
	return p.coeffs[0]
}

// Check a private share against a public commitment polynomial.
func (p *PubPoly) Check(s *share.PriShare) bool {
	pv := p.Eval(s.I)
	ps := p.G.Point().Mul(s.V, p.B)
	return pv.V.Equal(ps)
}
