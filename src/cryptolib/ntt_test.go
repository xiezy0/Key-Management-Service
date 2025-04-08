package crypto

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/stretchr/testify/assert"
	"math/big"
	randm "math/rand"
	"testing"
)

// 生成随机标量
func randomScalar() *big.Int {
	s, _ := rand.Int(rand.Reader, fr.Modulus())
	return s
}

// 生成随机 G1 点
func randomG1() bls12381.G1Affine {
	_, _, g, _ := bls12381.Generators()
	s := randomScalar()
	var p bls12381.G1Affine
	p.ScalarMultiplication(&g, s)
	return p
}

// 生成随机 G2 点
func randomG2() bls12381.G2Affine {
	_, _, _, h := bls12381.Generators()
	s := randomScalar()
	var p bls12381.G2Affine
	p.ScalarMultiplication(&h, s)
	return p
}

func BenchmarkG1ScalarMul(b *testing.B) {
	_, _, g, _ := bls12381.Generators()
	s := randomScalar()
	p := randomG1()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// 使用不同的点防止缓存优化
		if i%2 == 0 {
			p.ScalarMultiplication(&g, s)
		} else {
			p.ScalarMultiplication(&p, s)
		}
	}
}

func BenchmarkG2ScalarMul(b *testing.B) {
	_, _, _, h := bls12381.Generators()
	s := randomScalar()
	p := randomG2()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// 使用不同的点防止缓存优化
		if i%2 == 0 {
			p.ScalarMultiplication(&h, s)
		} else {
			p.ScalarMultiplication(&p, s)
		}
	}
}

// 生成随机标量域 Fr 元素
func randomFrElement() fr.Element {
	var e fr.Element
	e.SetRandom() // 使用密码学安全随机数
	return e
}

// 预热缓存并防止编译优化
var globalSinkFr fr.Element

func BenchmarkFrMultiplication(b *testing.B) {
	// 预生成测试数据（避免计入计时）
	data := make([]fr.Element, b.N+2)
	for i := range data {
		data[i] = randomFrElement()
	}

	b.ReportAllocs()
	b.ResetTimer()

	// 交叉存取策略防止优化
	for i := 0; i < b.N; i++ {
		a := data[i]
		b := data[i+1]
		var c fr.Element
		c.Mul(&a, &b)         // 标量域乘法
		globalSinkFr = c      // 防止优化
		data[i+2] = data[i+1] // 打破缓存局部性
	}
}

func TestRecovery(ti *testing.T) {
	// 初始化测试参数
	threshold := 7
	secret := fr.NewElement(123)
	//secretError := fr.NewElement(233)

	// 创建多项式
	poly, _ := NewPriPoly(threshold, secret)

	// 生成足够多的份额（包含冗余）
	n := 22
	shares := poly.FastShares(n)

	// 测试用例1: 使用前t个份额恢复
	ti.Run("first t shares", func(t *testing.T) {
		recovered, err := RecoverFastSecret(shares[:threshold], threshold)
		assert.NoError(t, err)
		assert.True(t, recovered.Equal(&secret))
	})

	// 测试用例2: 使用随机位置的t个份额
	ti.Run("random positions", func(t *testing.T) {
		selected := make([]FastPriShare, threshold)
		perm := randm.Perm(len(shares))[:threshold]
		for i, idx := range perm {
			selected[i] = shares[idx]
		}
		recovered, err := RecoverFastSecret(selected, threshold)
		assert.NoError(t, err)
		assert.True(t, recovered.Equal(&secret))
	})

	// 测试用例3: 使用冗余份额恢复（超过t个）
	ti.Run("extra shares", func(t *testing.T) {
		selected := shares[1 : 1+threshold] // 取5个份额（实际只用前t个）
		recovered, err := RecoverFastSecret(selected, threshold)
		assert.NoError(t, err)
		assert.True(t, recovered.Equal(&secret))
	})

	// 错误测试用例
	ti.Run("insufficient shares", func(t *testing.T) {
		_, err := RecoverFastSecret(shares[:threshold-1], threshold)
		assert.ErrorContains(t, err, "insufficient")
	})
}

func BenchmarkFastShare(b *testing.B) {
	// 初始化测试参数
	threshold := 85
	n := 256
	//threshold := 1
	//n := 4
	//threshold := 100
	//n := 301
	secret := fr.NewElement(123)
	//secretError := fr.NewElement(233)
	// 创建多项式
	poly, _ := NewPriPoly(threshold, secret)
	// 生成足够多的份额（包含冗余）
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 使用不同的点防止缓存优化
		poly.FastShares(n)
	}
}

func BenchmarkShare(b *testing.B) {
	// 初始化测试参数
	threshold := 85
	n := 256
	//threshold := 1
	//n := 4
	//threshold := 100
	//n := 301
	secret := fr.NewElement(123)
	//secretError := fr.NewElement(233)
	// 创建多项式
	poly, _ := NewPriPoly(threshold, secret)
	// 生成足够多的份额（包含冗余）
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 使用不同的点防止缓存优化
		poly.Shares(n)
	}
}

func TestFFT(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 6
	properties := gopter.NewProperties(parameters)

	for maxSize := 2; maxSize <= 1<<10; maxSize <<= 1 {

		domainWithPrecompute := fft.NewDomain(uint64(maxSize))
		domainWithoutPrecompute := fft.NewDomain(uint64(maxSize), fft.WithoutPrecompute())

		for domainName, domain := range map[string]*fft.Domain{
			"with precompute":    domainWithPrecompute,
			"without precompute": domainWithoutPrecompute,
		} {
			domainName := domainName
			domain := domain
			t.Logf("domain: %s", domainName)
			properties.Property("DIF FFT should be consistent with dual basis", prop.ForAll(

				// checks that a random evaluation of a dual function eval(gen**ithpower) is consistent with the FFT result
				func(ithpower int) bool {

					pol := make([]fr.Element, maxSize)
					backupPol := make([]fr.Element, maxSize)

					for i := 0; i < maxSize; i++ {
						pol[i].SetRandom()
					}
					copy(backupPol, pol)

					domain.FFT(pol, fft.DIF)
					fft.BitReverse(pol)

					sample := domain.Generator
					sample.Exp(sample, big.NewInt(int64(ithpower)))

					eval := evaluatePolynomial(backupPol, sample)

					return eval.Equal(&pol[ithpower])

				},
				gen.IntRange(0, maxSize-1),
			))

			properties.Property("DIF FFT on cosets should be consistent with dual basis", prop.ForAll(

				// checks that a random evaluation of a dual function eval(gen**ithpower) is consistent with the FFT result
				func(ithpower int) bool {

					pol := make([]fr.Element, maxSize)
					backupPol := make([]fr.Element, maxSize)

					for i := 0; i < maxSize; i++ {
						pol[i].SetRandom()
					}
					copy(backupPol, pol)

					domain.FFT(pol, fft.DIF, fft.OnCoset())
					fft.BitReverse(pol)

					sample := domain.Generator
					sample.Exp(sample, big.NewInt(int64(ithpower))).
						Mul(&sample, &domain.FrMultiplicativeGen)

					eval := evaluatePolynomial(backupPol, sample)

					return eval.Equal(&pol[ithpower])

				},
				gen.IntRange(0, maxSize-1),
			))

			properties.Property("DIT FFT should be consistent with dual basis", prop.ForAll(

				// checks that a random evaluation of a dual function eval(gen**ithpower) is consistent with the FFT result
				func(ithpower int) bool {

					pol := make([]fr.Element, maxSize)
					backupPol := make([]fr.Element, maxSize)

					for i := 0; i < maxSize; i++ {
						pol[i].SetRandom()
					}
					copy(backupPol, pol)

					fft.BitReverse(pol)
					domain.FFT(pol, fft.DIT)

					sample := domain.Generator
					sample.Exp(sample, big.NewInt(int64(ithpower)))

					eval := evaluatePolynomial(backupPol, sample)

					return eval.Equal(&pol[ithpower])

				},
				gen.IntRange(0, maxSize-1),
			))

			properties.Property("bitReverse(DIF FFT(DIT FFT (bitReverse))))==id", prop.ForAll(

				func() bool {

					pol := make([]fr.Element, maxSize)
					backupPol := make([]fr.Element, maxSize)

					for i := 0; i < maxSize; i++ {
						pol[i].SetRandom()
					}
					copy(backupPol, pol)

					fft.BitReverse(pol)
					domain.FFT(pol, fft.DIT)
					domain.FFTInverse(pol, fft.DIF)
					fft.BitReverse(pol)

					check := true
					for i := 0; i < len(pol); i++ {
						check = check && pol[i].Equal(&backupPol[i])
					}
					return check
				},
			))

			for nbCosets := 2; nbCosets < 5; nbCosets++ {
				properties.Property(fmt.Sprintf("bitReverse(DIF FFT(DIT FFT (bitReverse))))==id on %d cosets", nbCosets), prop.ForAll(

					func() bool {

						pol := make([]fr.Element, maxSize)
						backupPol := make([]fr.Element, maxSize)

						for i := 0; i < maxSize; i++ {
							pol[i].SetRandom()
						}
						copy(backupPol, pol)

						check := true

						for i := 1; i <= nbCosets; i++ {

							fft.BitReverse(pol)
							domain.FFT(pol, fft.DIT, fft.OnCoset())
							domain.FFTInverse(pol, fft.DIF, fft.OnCoset())
							fft.BitReverse(pol)

							for i := 0; i < len(pol); i++ {
								check = check && pol[i].Equal(&backupPol[i])
							}
						}

						return check
					},
				))
			}

			properties.Property("DIT FFT(DIF FFT)==id", prop.ForAll(

				func() bool {

					pol := make([]fr.Element, maxSize)
					backupPol := make([]fr.Element, maxSize)

					for i := 0; i < maxSize; i++ {
						pol[i].SetRandom()
					}
					copy(backupPol, pol)

					domain.FFTInverse(pol, fft.DIF)
					domain.FFT(pol, fft.DIT)

					check := true
					for i := 0; i < len(pol); i++ {
						check = check && (pol[i] == backupPol[i])
					}
					return check
				},
			))

			properties.Property("DIT FFT(DIF FFT)==id on cosets", prop.ForAll(

				func() bool {

					pol := make([]fr.Element, maxSize)
					backupPol := make([]fr.Element, maxSize)

					for i := 0; i < maxSize; i++ {
						pol[i].SetRandom()
					}
					copy(backupPol, pol)

					domain.FFTInverse(pol, fft.DIF, fft.OnCoset())
					domain.FFT(pol, fft.DIT, fft.OnCoset())

					for i := 0; i < len(pol); i++ {
						if !(pol[i].Equal(&backupPol[i])) {
							return false
						}
					}

					// compute with nbTasks == 1
					domain.FFTInverse(pol, fft.DIF, fft.OnCoset(), fft.WithNbTasks(1))
					domain.FFT(pol, fft.DIT, fft.OnCoset(), fft.WithNbTasks(1))

					for i := 0; i < len(pol); i++ {
						if !(pol[i].Equal(&backupPol[i])) {
							return false
						}
					}

					return true
				},
			))
		}
		properties.TestingRun(t, gopter.ConsoleReporter(false))
	}

}

// horner polynomial evaluation
func evaluatePolynomial(pol []fr.Element, val fr.Element) fr.Element {
	var acc, res, tmp fr.Element
	res.Set(&pol[0])
	acc.Set(&val)
	for i := 1; i < len(pol); i++ {
		tmp.Mul(&acc, &pol[i])
		res.Add(&res, &tmp)
		acc.Mul(&acc, &val)
	}
	return res
}
