package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
)

/*
  Practice using the encryption methods denoted in the crypto/cipher package.
  All of the code here is just minor modifications of the examples found on the
  goDoc page for that package. https://golang.org/pkg/crypto/cipher
*/

func encryptCBC(key []byte, message []byte) []byte {

	if len(message)%aes.BlockSize != 0 {
		//add padding
		padding := make([]byte, aes.BlockSize-(len(message)%aes.BlockSize))
		message = append(message, padding...)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(message))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], message)

	fmt.Printf("%x\n", ciphertext)
	return ciphertext
}

func decryptCBC(ciphertext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(ciphertext, ciphertext)

	fmt.Printf("%s\n", ciphertext)
	return ciphertext
}

func encryptCFB(key []byte, message []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(message))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], message)

	fmt.Printf("%x\n", ciphertext)
	return ciphertext
}

func decryptCFB(ciphertext []byte, key []byte) []byte {
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

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)
	fmt.Printf("%s", ciphertext)
	return ciphertext
}

func main() {
	key := []byte("Hello, my name i")
	testToEncode, err := ioutil.ReadFile("./plaintext.txt")
	if err != nil {
		panic(err)
	}

	cipher := encryptCBC(key, testToEncode)
	_ = decryptCBC(cipher, key)

	cipher2 := encryptCFB(key, testToEncode)
	_ = decryptCFB(cipher2, key)

}
