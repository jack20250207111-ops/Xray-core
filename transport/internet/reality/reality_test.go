package reality

import (
	"encoding/base64"
	"testing"

	"github.com/xtls/xray-core/common/crypto"
)

func TestEncryptedPaddingValueDecrypts(t *testing.T) {
	authKey := []byte("0123456789abcdef0123456789abcdef")
	value := encryptedPaddingValue(authKey, 64)
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("encrypted padding is not base64url: %v", err)
	}

	aead := crypto.NewAesGcm(authKey)
	if len(decoded) != aead.NonceSize()+64+aead.Overhead() {
		t.Fatalf("unexpected encrypted padding size: got %d, want %d", len(decoded), aead.NonceSize()+64+aead.Overhead())
	}
	if _, err := aead.Open(nil, decoded[:aead.NonceSize()], decoded[aead.NonceSize():], []byte("REALITY padding")); err != nil {
		t.Fatalf("failed to decrypt padding: %v", err)
	}
}

func TestEncryptedPaddingValueIsRandomized(t *testing.T) {
	authKey := []byte("0123456789abcdef0123456789abcdef")
	first := encryptedPaddingValue(authKey, 32)
	second := encryptedPaddingValue(authKey, 32)
	if first == second {
		t.Fatal("encrypted padding should be randomized")
	}
}
