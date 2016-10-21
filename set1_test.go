package cryptopals

import (
	"encoding/base64"
	"io/ioutil"
	"strings"
	"testing"
)

func TestHex2base64(t *testing.T) {
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	if got := Hex2base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"); got != want {
		t.Errorf("Hex2base64() = %q want %q", got, want)
	}
}

func TestXor(t *testing.T) {
	want := "746865206b696420646f6e277420706c6179"
	if got := Xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"); got != want {
		t.Errorf("Hex2base64() = %q want %q", got, want)
	}
}

func TestDecryptWithSingleByteXorCypher(t *testing.T) {
	want := "Cooking MC's like a pound of bacon"
	if got := DecryptWithSingleByteXorCypher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"); got.message != want {
		t.Errorf("DecryptWithSingleByteXorCypher() = %q want %q", got, want)
	}
}

func TestDetectSingleCharacterXor(t *testing.T) {
	dat, err := ioutil.ReadFile("./4.txt")
	if err != nil {
		panic(err)
	}
	want := "Now that the party is jumping\n"
	if got := DetectSingleCharacterXor(strings.Split(string(dat), "\n")); got != want {
		t.Errorf("DetectSingleCharacterXor() = %s want %s", got, want)
	}
}

func TestEncryptWithRepeatingKeyXor(t *testing.T) {
	want := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	if got := EncryptWithRepeatingKeyXor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE"); got != want {
		t.Errorf("DetectSingleCharacterXor() = %q want %q", got, want)
	}
}

func TestEditDistance(t *testing.T) {
	want := 37
	if got := editDistance([]byte("this is a test"), []byte("wokka wokka!!!")); got != want {
		t.Errorf("editDistance() = %v want %v", got, want)
	}
}

func TestBreakRepeatingKeyXor(t *testing.T) {
	dat, err := ioutil.ReadFile("./6.txt")
	if err != nil {
		panic(err)
	}

	want, err := ioutil.ReadFile("./6_test.txt")

	if got := BreakRepeatingKeyXor(string(dat)); got != string(want) {
		t.Errorf("BreakRepeatingKeyXor() = %s want %v", got, string(want))
	}
}

func TestFindRepeatingKeyLength(t *testing.T) {
	dat, err := ioutil.ReadFile("./6.txt")
	if err != nil {
		panic(err)
	}
	want := 29
	decoded, _ := base64.StdEncoding.DecodeString(string(dat))
	if got := findRepeatingKeyLength(decoded); got != want {
		t.Errorf("findRepeatingKeyLength() = %v want %v", got, want)
	}
}

func TestAESDecrypt(t *testing.T) {
	dat, err := ioutil.ReadFile("./7.txt")
	if err != nil {
		panic(err)
	}

	decoded, _ := base64.StdEncoding.DecodeString(string(dat))

	want, err := ioutil.ReadFile("./7_test.txt")
	if err != nil {
		panic(err)
	}

	if got := AESDecrypt(decoded, "YELLOW SUBMARINE"); string(got) != string(want) {
		t.Errorf("AESDecrypt() = %s want %s", got, want)
	}
}
