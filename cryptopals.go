package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Hex2base64 converts a hex string to base64
func Hex2base64(s string) string {
	decoded, _ := hex.DecodeString(s)
	return base64.StdEncoding.EncodeToString(decoded)
}

// Xor produces the XOR combination of two equal-length buffers
func Xor(s1, s2 string) string {
	s1Decoded, _ := hex.DecodeString(s1)
	s2Decoded, _ := hex.DecodeString(s2)

	return xorBytes(s1Decoded, s2Decoded)
}

func xorBytes(s1, s2 []byte) string {
	result := make([]byte, len(s1))

	for i := range s1 {
		result[i] = s1[i] ^ s2[i]
	}

	return fmt.Sprintf("%x", result)
}

// Candidate describes a potential decrypted message
type Candidate struct {
	cypher  []byte
	score   float64
	message string
}

// DecryptWithSingleByteXorCypher decrypts a message
func DecryptWithSingleByteXorCypher(encoded string) Candidate {
	candidates := make([]Candidate, 128)
	repetitions := len(encoded) / 2
	bytesMessage, _ := hex.DecodeString(encoded)

	for i := range candidates {
		bs := make([]byte, 1)
		binary.PutUvarint(bs, uint64(i))
		cypher := bytes.Repeat(bs, repetitions)
		candidate, _ := hex.DecodeString(xorBytes(bytesMessage, cypher))
		candidates[i] = Candidate{message: string(candidate), cypher: bs}
	}

	winner := candidates[0]
	maxScore := score(winner.message)

	// fmt.Println("------------------------------------------------------------------------------------------------")

	for _, v := range candidates {
		if v.score = score(v.message); v.score > maxScore {
			winner = v
			maxScore = v.score
		}

		// fmt.Printf("%s: %s (%v)\n", string(v.cypher), v.message[:30], v.score)
		// fmt.Println("----------------------------------------------------------")
	}
	// fmt.Println("####################################################################################################")

	return winner
}

func score(message string) float64 {
	score := 0.0
	for _, v := range strings.Split(message, "") {
		if strings.IndexAny(v, "AEIOUYaeiouy ") != -1 {
			score++
		}

		if strings.IndexAny(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ") != -1 {
			score++
		}

		if strings.IndexAny(v, "{}\\/%~`><+*#@&éèàç§\"\n=|^") != -1 {
			score--
		}
	}
	return score
}

// DetectSingleCharacterXor finds the string that has been encrypted with a single character XOR
func DetectSingleCharacterXor(strings []string) string {
	maxScore := 0.0
	winner := strings[0]

	for _, s := range strings {
		if candidate := DecryptWithSingleByteXorCypher(s); candidate.score > maxScore {
			maxScore = candidate.score
			winner = candidate.message
		}
	}

	return winner
}

// EncryptWithRepeatingKeyXor encrypts a string with a repeating-key XOR
func EncryptWithRepeatingKeyXor(s, key string) string {
	repeatingKey := strings.Repeat(key, len(s)/len(key)+1)
	return xorBytes([]byte(s), []byte(repeatingKey))
}

func editDistance(s1, s2 []byte) int {
	distance := 0

	for i, b := range s1 {
		for shift := uint(0); shift < 8; shift++ {
			isDifferent := ((b >> shift) ^ (s2[i] >> shift)) & 1
			if isDifferent > 0 {
				distance++
			}
		}
	}

	return distance
}

// BreakRepeatingKeyXor decrypts a message encoded with a repeating key XOR
func BreakRepeatingKeyXor(s string) string {
	decoded, _ := base64.StdEncoding.DecodeString(s)

	keyLength := findRepeatingKeyLength(decoded)

	groups := make([][]byte, keyLength)

	for i, v := range decoded {
		groups[i%keyLength] = append(groups[i%keyLength], v)
	}

	cyphers := make([][]byte, keyLength)
	for i, v := range groups {
		c := DecryptWithSingleByteXorCypher(hex.EncodeToString(v))
		cyphers[i] = c.cypher
	}
	var blank []byte
	finalCypher := bytes.Join(cyphers, blank)

	hexString := EncryptWithRepeatingKeyXor(string(decoded), string(finalCypher))
	result, _ := hex.DecodeString(hexString)
	return string(result)
}

func findRepeatingKeyLength(s []byte) int {
	smallestEdit := 99.0
	repeatingKeyLength := 0

	for keysize := 2; keysize <= 40; keysize++ {

		blocks := make([][]byte, 4)

		for i := range blocks {
			blocks[i] = s[i*keysize : (i+1)*keysize]
		}

		distance := 0.0

		for _, b1 := range blocks {
			for _, b2 := range blocks {
				distance += float64(editDistance(b1, b2))
			}
		}

		distance = distance / float64(keysize)

		if distance < smallestEdit {
			smallestEdit = distance
			repeatingKeyLength = keysize
		}
	}
	return repeatingKeyLength
}

// AESDecrypt decrypts from AES ECB
func AESDecrypt(ciphertext []byte, key string) []byte {
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}

	bs := cipher.BlockSize()
	if len(ciphertext)%bs != 0 {
		panic("Need a multiple of the blocksize")
	}

	i := 0
	plaintext := make([]byte, len(ciphertext))
	finalplaintext := make([]byte, len(ciphertext))
	for len(ciphertext) > 0 {
		cipher.Decrypt(plaintext, ciphertext)
		ciphertext = ciphertext[bs:]
		decryptedBlock := plaintext[:bs]
		for index, element := range decryptedBlock {
			finalplaintext[(i*bs)+index] = element
		}
		i++
		plaintext = plaintext[bs:]
	}
	return finalplaintext[:len(finalplaintext)-5]
}

func DetectAESinECBMode(ciphertexts []strings) string {

	for cyphertext := range ciphertexts {

	}
}
