package hacss_bk_gc

import (
	"encoding/json"
	"errors"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"math/big"
	"math/bits"
	"sort"
)

type PriPoly struct {
	coeffs []fr.Element // Coefficients of the polynomial（BLS12-381的标量场）
}

// PubPoly表示对秘密共享多项式的公开承诺多项式
type PubPoly struct {
	B       *bls12381.G1Affine  // 基点，nil表示标准基点
	Commits []bls12381.G1Affine // 对秘密多项式系数的承诺（G1群元素）
}

type PubPolyBytes struct {
	B       []byte   // 基点的序列化，nil表示标准基
	Commits [][]byte // 承诺的序列化
}

type PubShare struct {
	I int
	V bls12381.G1Affine // G1群元素
}

type PriShare struct {
	I int        // 私钥份额的索引
	V fr.Element // BLS12-381标量场元素
}

// FastPriShare 使用NTT优化的快速份额结构
type FastPriShare struct {
	X fr.Element // 点的x值（标量域）
	V fr.Element // 值份额（标量域）
}

// PriShare represents a private share.
type PriShareBytes struct {
	I int    // Index of the private share
	V []byte // Value of the private share
}

// NewPriPoly 创建BLS12-381版本的新秘密多项式
func NewPriPoly(t int, s fr.Element) *PriPoly {
	coeffs := make([]fr.Element, t)
	coeffs[0] = s
	for i := 1; i < t; i++ {
		var tmp fr.Element
		tmp.SetRandom() // 使用BLS12-381的随机数生成方法
		coeffs[i] = tmp
	}
	return &PriPoly{coeffs: coeffs}
}

// Commit 创建BLS12-381 G1群的承诺多项式
func (p *PriPoly) Commit() *PubPoly {
	commits := make([]bls12381.G1Affine, p.Threshold())
	for i := range commits {
		scalarBigInt := new(big.Int)
		p.coeffs[i].BigInt(scalarBigInt) // 正确转换方式

		// 使用G1生成元进行标量乘法
		var tmp bls12381.G1Affine
		tmp.ScalarMultiplicationBase(scalarBigInt)
		commits[i] = tmp
	}
	return &PubPoly{
		B:       nil, // 默认使用G1生成元
		Commits: commits,
	}
}

func SerializePriShare(p *PriShare) ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	// 序列化fr.Element
	vBytes := p.V.Bytes()
	share := &PriShareBytes{
		I: p.I,
		V: vBytes[:], // fr.Element的固定长度字节数组
	}
	return json.Marshal(share)
}

func DeserializePriShare(prisharebytes []byte) (*PriShare, error) {
	if len(prisharebytes) == 0 {
		return nil, nil
	}

	var priShareBytes PriShareBytes
	if err := json.Unmarshal(prisharebytes, &priShareBytes); err != nil {
		return nil, err
	}

	var v fr.Element
	v.SetBytes(priShareBytes.V)

	return &PriShare{
		I: priShareBytes.I,
		V: v,
	}, nil
}

func (p *PubPoly) SerializePubPoly() ([]byte, error) {
	var B_serilize []byte
	if p.B != nil {
		B_serilize = p.B.Marshal()
	}

	Commit_temp := make([][]byte, len(p.Commits))
	for i := range p.Commits {
		Commit_temp[i] = p.Commits[i].Marshal()
	}

	pub := &PubPolyBytes{
		B:       B_serilize,
		Commits: Commit_temp,
	}
	return json.Marshal(pub)
}

func DeserializePubPoly(pubBytes []byte) (*PubPoly, error) {
	var pubPolyBytes PubPolyBytes
	if err := json.Unmarshal(pubBytes, &pubPolyBytes); err != nil {
		return nil, err
	}

	pubPoly := &PubPoly{}

	// 反序列化基点
	if pubPolyBytes.B != nil {
		pubPoly.B = new(bls12381.G1Affine)
		if err := pubPoly.B.Unmarshal(pubPolyBytes.B); err != nil {
			return nil, err
		}
	} // nil保持默认基点

	// 反序列化承诺
	pubPoly.Commits = make([]bls12381.G1Affine, len(pubPolyBytes.Commits))
	for i, commitBytes := range pubPolyBytes.Commits {
		if err := pubPoly.Commits[i].Unmarshal(commitBytes); err != nil {
			return nil, err
		}
	}

	return pubPoly, nil
}

// Threshold returns the secret sharing threshold.
func (p *PriPoly) Threshold() int {
	return len(p.coeffs)
}

// Shares creates a list of n private shares p(1),...,p(n).
func (p *PriPoly) Shares(n int) []*PriShare {
	shares := make([]*PriShare, n)
	for i := range shares {
		shares[i] = p.Eval(i)
	}
	return shares
}

// FastShares 使用NTT生成n个快速份额
func (p *PriPoly) FastShares(n int) []*PriShare {
	m := nextPowerOfTwo(n)
	domain := fft.NewDomain(uint64(m))

	// zero padding
	coeffs := make([]fr.Element, m)
	copy(coeffs, p.coeffs)
	for i := len(p.coeffs); i < m; i++ {
		coeffs[i] = *new(fr.Element).SetInt64(0)
	}

	// freq to point
	domain.FFT(coeffs, fft.DIF)
	fft.BitReverse(coeffs)

	shares := make([]*PriShare, n)
	g := domain.Generator

	for i := 0; i < n; i++ {
		// 计算x_i = g^i
		xi := new(fr.Element).Set(&g)
		xi.Exp(*xi, big.NewInt(int64(i)))

		shares[i] = &PriShare{
			I: i,
			V: coeffs[i],
		}
	}
	return shares
}

// nextPowerOfTwo 计算大于等于n的最小2的幂
func nextPowerOfTwo(n int) int {
	return 1 << (bits.Len(uint(n - 1)))
}

// Eval 计算私有份额 v = p(i)
func (p *PriPoly) Eval(i int) *PriShare {
	// 计算x_i = i+1（通常索引从1开始）
	xi := fr.NewElement(uint64(i + 1))

	// 使用霍纳法计算多项式值
	var v fr.Element
	for j := len(p.coeffs) - 1; j >= 0; j-- {
		v.Mul(&v, &xi)          // v = v * x_i
		v.Add(&v, &p.coeffs[j]) // v = v + coeffs[j]
	}

	return &PriShare{I: i, V: v}
}

// GenRPoly 生成随机多项式（阈值式）
func GenRPoly(thre_p int, s fr.Element) *PriPoly {
	coeffs := make([]fr.Element, thre_p)
	coeffs[0] = s // 常数项设为秘密值

	// 生成随机系数（从x^1到x^{t-1}）
	for i := 1; i < thre_p; i++ {
		coeffs[i].SetRandom() // 使用bls12-381的随机数生成
	}

	return &PriPoly{coeffs: coeffs}
}

func GenRPloy(thre_p int, s fr.Element) *PriPoly {
	return NewPriPoly(thre_p, s)
}

// GenSecret 生成随机标量秘密
func GenSecret() fr.Element {
	var secret fr.Element
	secret.SetRandom() // 使用bls12-381的随机数生成
	return secret
}
func GenRPloyCommitment(R_Ploy *PriPoly) *PubPoly {
	return R_Ploy.Commit()
}

func GenRPloyShares(R_Ploy *PriPoly, n int) []*PriShare {
	return R_Ploy.Shares(n)
}

func FastGenRPloyShares(R_Ploy *PriPoly, n int) []*PriShare {
	return R_Ploy.FastShares(n)
}

func GenSSharePoly(t int, n int, R_Poly_shares []*PriShare) []*PriPoly {
	S_Share_Poly := make([]*PriPoly, n)
	for i := 0; i < n; i++ {
		S_Share_Poly[i] = GenSSharePolySwithR(t, i+1, R_Poly_shares[i])
	}
	return S_Share_Poly
}

func GenSSharePolySwithR(t int, i int, r_j *PriShare) *PriPoly {
	coeffs := make([]fr.Element, t+1)

	// 计算x_i = i（注意索引可能需要+1，根据实际协议调整）
	xi := fr.NewElement(uint64(i))

	var x fr.Element // 初始值为0

	// 初始化系数：常数项为0，其他项随机
	for idx := range coeffs {
		if idx == 0 {
			coeffs[0].SetZero() // 显式设置为0
		} else {
			coeffs[idx].SetRandom() // 生成随机系数
		}
	}
	// 使用霍纳法计算多项式值
	for j := t; j >= 0; j-- {
		x.Mul(&x, &xi)        // x = x * x_i
		x.Add(&x, &coeffs[j]) // x = x + coeffs[j]
	}
	// 调整常数项：coeffs[0] = r_j.V - x
	coeffs[0].Sub(&r_j.V, &x)

	return &PriPoly{coeffs: coeffs}
}

func FastGenSSharePoly(t int, n int, domain *fft.Domain, R_Poly_shares []*FastPriShare) []*PriPoly {
	S_Share_Poly := make([]*PriPoly, n)

	for i := 0; i < n; i++ {
		S_Share_Poly[i] = FastGenSSharePolySwithR(t, i+1, domain, R_Poly_shares[i])
	}
	return S_Share_Poly
}

func FastGenSSharePolySwithR(t int, i int, domain *fft.Domain, r_j *FastPriShare) *PriPoly {
	coeffs := make([]fr.Element, t+1)
	coeffs[0].SetZero() // 初始常数项为0

	// 生成随机系数（t次多项式）
	for idx := 1; idx <= t; idx++ {
		coeffs[idx].SetRandom()
	}

	// 准备NTT计算
	m := domain.Cardinality
	paddedCoeffs := make([]fr.Element, m)
	copy(paddedCoeffs, coeffs)
	for j := t + 1; j < int(m); j++ {
		paddedCoeffs[j] = *new(fr.Element).SetZero()
	}

	// 执行FFT变换（系数到点值）
	domain.FFT(paddedCoeffs, fft.DIF)
	fft.BitReverse(paddedCoeffs)

	// 获取x_i对应的点值（i-1因为索引从0开始）
	idx := i - 1
	if idx >= int(m) {
		panic("evaluation index exceeds FFT domain size")
	}
	sum := paddedCoeffs[idx] // 获取未调整前的多项式值

	// 调整常数项使f(i) = r_j.V
	coeffs[0].Sub(&r_j.V, &sum)

	return &PriPoly{
		coeffs: coeffs[:t+1], // 保留原始系数长度
	}
}

func GenSSharePolyCommitment(S_Poly []*PriPoly, n int) []*PubPoly {
	S_Poly_Commitment := make([]*PubPoly, n)
	for i := 0; i < n; i++ {
		S_Poly_Commitment[i] = S_Poly[i].Commit()
	}
	return S_Poly_Commitment
}

func GenSSharePolyShares(S_Poly []*PriPoly, n int) [][]*PriShare {
	S_Share_Poly_Shares := make([][]*PriShare, 0)
	for i := 0; i < n; i++ {
		S_Share_Poly_Shares = append(S_Share_Poly_Shares, S_Poly[i].Shares(n))
	}
	return S_Share_Poly_Shares
}

func FastGenSSharePolyShares(S_Poly []*PriPoly, n int) [][]*PriShare {
	S_Share_Poly_Shares := make([][]*PriShare, 0)
	for i := 0; i < n; i++ {
		S_Share_Poly_Shares = append(S_Share_Poly_Shares, S_Poly[i].FastShares(n))
	}
	return S_Share_Poly_Shares
}

// Shares creates a list of n public commitment shares p(1),...,p(n).
func (p *PubPoly) Shares(n int) []*PubShare {
	shares := make([]*PubShare, n)
	for i := range shares {
		shares[i] = p.Eval(i)
	}
	return shares
}

// Threshold returns the secret sharing threshold.
func (p *PubPoly) Threshold() int {
	return len(p.Commits)
}

func (p *PubPoly) Eval(i int) *PubShare {
	// 生成x_i = i+1（索引从1开始）
	xi := fr.NewElement(uint64(i + 1))
	xiBig := xi.BigInt(new(big.Int)) // 转换为big.Int类型用于标量乘法

	// 使用Jacobian坐标进行高效计算
	var vJac bls12381.G1Jac
	vJac.X.SetOne()  // 任意X坐标（标准做法）
	vJac.Y.SetOne()  // 任意Y坐标（标准做法）
	vJac.Z.SetZero() // Z=0 表示无穷远点

	// 倒序遍历承诺（假设Commits按升幂排列：c_0, c_1,...c_{t-1}）
	for j := len(p.Commits) - 1; j >= 0; j-- {
		// 标量乘法：v = v * x_i
		vJac.ScalarMultiplication(&vJac, xiBig)

		// 将G1Affine承诺转换为Jacobian格式并相加
		var commitJac bls12381.G1Jac
		commitJac.FromAffine(&p.Commits[j])
		vJac.AddAssign(&commitJac)
	}

	// 转换回Affine坐标
	var result bls12381.G1Affine
	result.FromJacobian(&vJac)

	return &PubShare{
		I: i,
		V: result,
	}
}

func GenRPolyPubShares(R_Ploy_Commitment *PubPoly, n int) []*PubShare {
	return R_Ploy_Commitment.Shares(n)
}

func GenSSharePolyPubShares(S_Poly_Commitment []*PubPoly, n int) [][]*PubShare {
	S_Share_Poly_Pub_Shares := make([][]*PubShare, 0)
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
func RecoverPriPoly(shares []*PriShare, t, n int) (*PriPoly, error) {
	x, y := xyScalar(shares, t, n)
	if len(x) != t {
		return nil, errors.New("share: not enough shares to recover private polynomial")
	}

	var accPoly *PriPoly
	var err error
	//den := G.Scalar()
	// Notations follow the Wikipedia article on Lagrange interpolation
	// https://en.wikipedia.org/wiki/Lagrange_polynomial
	for j := range x {
		basis := lagrangeBasis(j, x)
		for i := range basis.coeffs {
			yj := y[j]
			basis.coeffs[i] = *basis.coeffs[i].Mul(&basis.coeffs[i], &yj)
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

type byIndexScalar []*PriShare

func (s byIndexScalar) Len() int           { return len(s) }
func (s byIndexScalar) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s byIndexScalar) Less(i, j int) bool { return s[i].I < s[j].I }

// xyScalar returns the list of (x_i, y_i) pairs indexed. The first map returned
// is the list of x_i and the second map is the list of y_i, both indexed in
// their respective map at index i.
func xyScalar(shares []*PriShare, t, n int) (map[int]fr.Element, map[int]fr.Element) {
	// 排序逻辑不变（假设 PriShare.I 的类型兼容）
	sorted := make([]*PriShare, 0, n)
	for _, share := range shares {
		if share != nil {
			sorted = append(sorted, share)
		}
	}
	sort.Sort(byIndexScalar(sorted))

	x := make(map[int]fr.Element)
	y := make(map[int]fr.Element)
	var zero fr.Element // bls12-381 标量零值

	for _, s := range sorted {
		if s == nil || s.V.Equal(&zero) || s.I < 0 {
			// 使用 Equal 方法比较标量是否为零
			continue
		}
		idx := s.I

		// 创建 x 标量 (idx+1)
		var xScalar fr.Element
		xScalar.SetUint64(uint64(idx + 1)) // 使用 bls12-381 标量的 SetUint64

		x[idx] = xScalar
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
func lagrangeBasis(i int, xs map[int]fr.Element) *PriPoly {
	// 初始化基多项式 L_i(x) = 1
	var one fr.Element
	one.SetOne() // bls12-381 标量 1
	basis := &PriPoly{
		coeffs: []fr.Element{one},
	}

	var den fr.Element
	acc := one // 累积分母 acc = 1

	// 遍历所有点计算拉格朗日基
	for m, xm := range xs {
		if i == m {
			continue
		}

		// 构造多项式 (x - xm)
		basis = basis.Mul(minusConst(xm))

		// 计算分母部分 den = 1/(x_i - x_m)
		xsi := xs[i]
		den.Sub(&xsi, &xm)  // den = x_i - x_m
		den.Inverse(&den)   // 使用 bls12-381 的逆元计算
		acc.Mul(&acc, &den) // 累积分母 acc *= den
	}

	// 将分母乘到所有系数上
	for idx := range basis.coeffs {
		basis.coeffs[idx].Mul(&basis.coeffs[idx], &acc)
	}
	return basis
}

// RecoverSecret 使用拉格朗日插值从私钥份额中恢复秘密 p(0)
func RecoverSecret(shares []*PriShare, t, n int) (fr.Element, error) {
	x, y := xyScalar(shares, t, n)
	if len(x) < t {
		return fr.Element{}, errors.New("share: not enough shares to recover secret")
	}

	var acc fr.Element // 累加器
	var num fr.Element // 分子项
	var den fr.Element // 分母项
	var tmp fr.Element // 临时变量

	// 遍历所有份额进行拉格朗日插值
	for i, xi := range x {
		yi := y[i]
		num.Set(&yi) // num = y_i

		den.SetOne() // den = 1
		for j, xj := range x {
			if i == j {
				continue
			}
			// 分子：num *= x_j
			num.Mul(&num, &xj)

			// 分母：den *= (x_j - x_i)
			tmp.Sub(&xj, &xi)
			den.Mul(&den, &tmp)
		}

		// 计算单项式：num / den
		den.Inverse(&den)   // 求分母的逆元
		tmp.Mul(&num, &den) // tmp = num * den^{-1}

		// 累加到结果
		acc.Add(&acc, &tmp)
	}

	return acc, nil
}

// Mul multiples p and q together. The result is a polynomial of the sum of
// the two degrees of p and q. NOTE: it does not check for null coefficients
// after the multiplication, so the degree of the polynomial is "always" as
// described above. This is only for use in secret sharing schemes. It is not
// a general polynomial multiplication routine.
// Mul 实现多项式乘法（仅限秘密共享场景使用）
func (p *PriPoly) Mul(q *PriPoly) *PriPoly {
	d1 := len(p.coeffs) - 1
	d2 := len(q.coeffs) - 1
	newDegree := d1 + d2
	coeffs := make([]fr.Element, newDegree+1) // 自动初始化为零值

	// 多项式乘法卷积计算
	for i := 0; i <= d1; i++ {
		for j := 0; j <= d2; j++ {
			var tmp fr.Element
			tmp.Mul(&p.coeffs[i], &q.coeffs[j]) // tmp = p[i] * q[j]
			coeffs[i+j].Add(&coeffs[i+j], &tmp) // 累加到对应位置
		}
	}
	return &PriPoly{coeffs: coeffs}
}

// minusConst 构造 (x - c) 多项式
func minusConst(c fr.Element) *PriPoly {
	neg := new(fr.Element).Neg(&c) // 计算 -c

	// 多项式表示为 [-c, 1]
	return &PriPoly{
		coeffs: []fr.Element{
			*neg,         // x^0 项系数
			{1, 0, 0, 0}, // x^1 项系数 (小端存储格式的 1)
		},
	}
}

// Some error definitions
var errorGroups = errors.New("non-matching groups")
var errorCoeffs = errors.New("different number of coefficients")

// Add computes the component-wise sum of the polynomials p and q and returns it
// as a new polynomial.
// Add 实现多项式系数相加 (组件级加法)
func (p *PriPoly) Add(q *PriPoly) (*PriPoly, error) {
	if len(p.coeffs) != len(q.coeffs) { // 假设原 Threshold() 判断简化为系数长度检查
		return nil, errors.New("coefficient length mismatch")
	}

	coeffs := make([]fr.Element, len(p.coeffs))
	for i := range coeffs {
		coeffs[i].Add(&p.coeffs[i], &q.coeffs[i]) // 组件加法
	}
	return &PriPoly{coeffs: coeffs}, nil
}

// Secret 返回多项式常数项 p(0)
func (p *PriPoly) Secret() fr.Element {
	return p.coeffs[0] // 直接返回标量值
}

// Check 验证私钥分享与公钥承诺的兼容性
func (p *PubPoly) Check(s *PriShare) bool {
	// 1. 获取公钥承诺在索引 s.I 处的评估值
	pv := p.Eval(s.I) // pv.V 类型为 bls12-381.G1Affine

	// 2. 将私钥份额转换为 G1 点: [s.V] * G1 生成器
	var ps bls12381.G1Affine

	// 获取 G1 生成器的仿射坐标形式 (预计算值)
	_, _, g1Aff, _ := bls12381.Generators()

	// 将 fr.Element 转换为适合标量乘法的格式
	var scalarBigInt big.Int
	s.V.BigInt(&scalarBigInt) // fr.Element -> big.Int

	// 执行标量乘法: ps = s.V * G1
	ps.ScalarMultiplication(&g1Aff, &scalarBigInt)

	// 3. 比较两个 G1 点是否相等 (安全的时间恒定比较)
	return pv.V.Equal(&ps)
}
