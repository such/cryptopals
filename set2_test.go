package cryptopals

import "testing"

func TestPKCS7Padding(t *testing.T) {
	want := "YELLOW SUBMARINE\x04\x04\x04\x04"
	if got := PKCS7Padding("YELLOW SUBMARINE", 20); got != want {
		t.Errorf("PKCS7Padding() = %x want %x", got, want)
	}
}

func TestAESEncrypt(t *testing.T) {
	message := "YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE"
	key := "YELLOW SUBMARINE"
	if got := AESDecrypt(AESEnccrypt([]byte(message), key), key); string(got) != message {
		t.Errorf("PKCS7Padding() = %x want %x", got, message)
	}
}
