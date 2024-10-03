package cryptolib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"os"

	"github.com/zenazn/pkcs7pad"
)

type CryptoLibrary int

var nid int64

const (
	NoCrypto CryptoLibrary = 0 // Return true for all operations. Used for testing and when there is an authenticated channel.
)

var TypeOfCrypto_name = map[int]CryptoLibrary{
	0: NoCrypto,
}

var cryptoOption CryptoLibrary

func GenMAC(id int64, msg []byte) []byte {
	result := []byte("")

	mac := hmac.New(sha256.New, []byte("123456789"))
	mac.Write(msg)
	result = mac.Sum(nil)

	return result
}

func VerifyMAC(id int64, msg []byte, sig []byte) bool {
	result := false

	mac := hmac.New(sha256.New, []byte("123456789"))
	mac.Write(msg)
	expectedMac := mac.Sum(nil)
	result = hmac.Equal(expectedMac, sig)

	return result
}

func StartCrypto(id int64, cryptoOpt int) {
	var exist bool
	nid = id
	cryptoOption, exist = TypeOfCrypto_name[cryptoOpt]
	if !exist {
		log.Fatalf("Crypto option is not supported")
		os.Exit(1)
	}

	switch cryptoOption {
	case NoCrypto:
		log.Printf("Alert. Not using any crypto library.")
	default:
		log.Fatalf("The crypto library is not supported by the system")
	}
}

func CBCEncrypterAES(plaintext []byte) []byte {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	plaintext = pkcs7pad.Pad(plaintext, aes.BlockSize)
	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	return ciphertext
}

func CBCDecrypterAES(ciphertext []byte) []byte {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	//ciphertext, _ := hex.DecodeString("73c86d43a9d700a253a96c85b0f6b03ac9792e0e757f869cca306bd3cba1c62b")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]

	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.
	//fmt.Printf("%s", ciphertext)
	//fmt.Println(len(ciphertext))
	ciphertext, _ = pkcs7pad.Unpad(ciphertext)
	return ciphertext
}
