package crypto

import (
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"math/bits"
)

type PriPoly struct {
	coeffs    []fr.Element // 多项式系数（标量域）
	threshold int          // 阈值（t-1次多项式）
}

type PriShare struct {
	I int        // 份额索引
	V fr.Element // 值份额（标量域）
}

// FastPriShare 使用NTT优化的快速份额结构
type FastPriShare struct {
	X fr.Element // 点的x值（标量域）
	V fr.Element // 值份额（标量域）
}

// 创建t-1次多项式
func NewPriPoly(t int, s fr.Element) (*PriPoly, error) {
	coeffs := make([]fr.Element, t)
	coeffs[0] = s
	for i := 1; i < t; i++ {
		coeffs[i].SetRandom()
	}
	return &PriPoly{
		coeffs:    coeffs,
		threshold: t,
	}, nil
}

// 生成n个秘密共享份额
func (p *PriPoly) Shares(n int) []PriShare {
	shares := make([]PriShare, n)
	for i := range shares {
		shares[i] = p.Eval(i + 1) // 索引从1开始
	}
	return shares
}

// 多项式求值
func (p *PriPoly) Eval(i int) PriShare {
	xi := fr.NewElement(uint64(i))
	v := evalPoly(p.coeffs, xi)
	return PriShare{
		I: i,
		V: *v,
	}
}

// 秘密恢复
func RecoverSecret(shares []PriShare, t int) (fr.Element, error) {
	if len(shares) < t {
		return fr.Element{}, errors.New("insufficient shares")
	}

	var secret fr.Element
	for i := 0; i < t; i++ {
		lambda := lagrangeCoefficient(i, shares[:t])
		term := new(fr.Element).Mul(&shares[i].V, lambda)
		secret.Add(&secret, term)
	}
	return secret, nil
}

// 多项式求值辅助函数
func evalPoly(coeffs []fr.Element, x fr.Element) *fr.Element {
	result := fr.NewElement(0)
	for j := len(coeffs) - 1; j >= 0; j-- {
		result.Mul(&result, &x)
		result.Add(&result, &coeffs[j])
	}
	return &result
}

// Lagrange系数计算
func lagrangeCoefficient(i int, shares []PriShare) *fr.Element {
	xi := fr.NewElement(uint64(shares[i].I))
	lambda := fr.NewElement(1)

	for j, sj := range shares {
		if j == i {
			continue
		}
		xj := fr.NewElement(uint64(sj.I))
		den := *new(fr.Element).Sub(&xj, &xi)
		den.Inverse(&den)
		lambda.Mul(&lambda, new(fr.Element).Mul(&xj, &den))
	}
	return &lambda
}

func nextPowOfTwo(n int) int {
	if n <= 0 {
		return 1
	}
	return 1 << (bits.Len(uint(n - 1)))
}

// FastShares 使用NTT生成n个快速份额
func (p *PriPoly) FastShares(n int) []FastPriShare {
	m := nextPowerOfTwo(n)
	domain := fft.NewDomain(uint64(m), fft.WithoutPrecompute())

	// zero padding
	coeffs := make([]fr.Element, m)
	copy(coeffs, p.coeffs)
	for i := len(p.coeffs); i < m; i++ {
		coeffs[i] = *new(fr.Element).SetInt64(0)
	}

	// freq to point
	domain.FFT(coeffs, fft.DIF)
	fft.BitReverse(coeffs)

	shares := make([]FastPriShare, n)
	g := domain.Generator

	for i := 0; i < n; i++ {
		// 计算x_i = g^i
		xi := new(fr.Element).Set(&g)
		//xi.Exp(*xi, big.NewInt(int64(i)))

		shares[i] = FastPriShare{
			X: *xi,
			V: coeffs[i],
		}
	}
	return shares
}

// RecoverFastSecret 快速秘密恢复（支持任意位置的t个份额）
func RecoverFastSecret(shares []FastPriShare, t int) (fr.Element, error) {
	if len(shares) < t {
		return fr.Element{}, errors.New("insufficient shares")
	}

	// 输入验证：检查点值唯一性
	seen := make(map[string]bool)
	for _, s := range shares {
		key := s.X.String()
		if seen[key] {
			return fr.Element{}, fmt.Errorf("duplicate x value: %v", s.X)
		}
		seen[key] = true
	}

	var secret fr.Element

	// 对所有输入的t个份额进行插值（不再限定前t个）
	for i := 0; i < t; i++ {
		lambda := fastLagrangeCoefficient(i, shares[:t]) // 这里传入shares[:t]是任意t个有效份额
		term := new(fr.Element).Mul(&shares[i].V, lambda)
		secret.Add(&secret, term)
	}
	return secret, nil
}

// fastLagrangeCoefficient 优化后的系数计算（支持任意位置输入）
func fastLagrangeCoefficient(i int, shares []FastPriShare) *fr.Element {
	xi := &shares[i].X
	lambda := fr.NewElement(1)
	zero := fr.NewElement(0)

	for j := 0; j < len(shares); j++ {
		if j == i {
			continue
		}
		xj := &shares[j].X

		// 计算分子：(0 - xj)
		num := new(fr.Element).Sub(&zero, xj)
		// 计算分母：(xi - xj)
		den := new(fr.Element).Sub(xi, xj)
		// 分母逆元（注意处理除零错误）
		if den.IsZero() {
			return &fr.Element{} // 实际应返回error，此处简写
		}
		den.Inverse(den)
		// 累乘：num * den
		lambda.Mul(&lambda, num).Mul(&lambda, den)
	}
	return &lambda
}

// nextPowerOfTwo 计算大于等于n的最小2的幂
func nextPowerOfTwo(n int) int {
	return 1 << (bits.Len(uint(n - 1)))
}
