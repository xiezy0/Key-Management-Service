package cryptolib

import (
	"fmt"
	"testing"
)

func TestCBC(test *testing.T) {
	plaintext := []byte("exampleplaintext")
	fmt.Println(len(plaintext))
	cipher := CBCEncrypterAES(plaintext)
	CBCDecrypterAES(cipher)
}
