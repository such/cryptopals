package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
)

// PKCS7Padding implements PKCS#7 padding of a string
func PKCS7Padding(text string, length int) string {
	paddingLength := length - (len(text) % length)

	bs := make([]byte, 1)
	binary.PutUvarint(bs, uint64(paddingLength))

	padding := bytes.Repeat(bs, paddingLength)

	return text + string(padding)
}

// CBCMode decrypts a ciphertext
func CBCMode(ciphertext, key, iv string) string {

	return ""
}

// AESEncrypt encrypts with AES ECB
func AESEnccrypt(plaintext []byte, key string) []byte {
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}

	bs := cipher.BlockSize()
	if len(plaintext)%bs != 0 {
		panic("Need a multiple of the blocksize")
	}

	ciphertext := make([]byte, len(plaintext))
	for len(plaintext) > 0 {
		cipher.Encrypt(ciphertext, plaintext)
		plaintext = plaintext[bs:]
		ciphertext = ciphertext[bs:]
	}

	return ciphertext
}
