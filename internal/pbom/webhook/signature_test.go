package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func computeSignature(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignature(t *testing.T) {
	secret := "test-secret-key"
	payload := []byte(`{"action":"completed"}`)

	tests := []struct {
		name      string
		payload   []byte
		signature string
		secret    string
		wantErr   bool
	}{
		{
			name:      "valid signature",
			payload:   payload,
			signature: computeSignature(payload, secret),
			secret:    secret,
			wantErr:   false,
		},
		{
			name:      "wrong secret",
			payload:   payload,
			signature: computeSignature(payload, "wrong-secret"),
			secret:    secret,
			wantErr:   true,
		},
		{
			name:      "tampered payload",
			payload:   []byte(`{"action":"tampered"}`),
			signature: computeSignature(payload, secret),
			secret:    secret,
			wantErr:   true,
		},
		{
			name:      "empty signature",
			payload:   payload,
			signature: "",
			secret:    secret,
			wantErr:   true,
		},
		{
			name:      "empty secret",
			payload:   payload,
			signature: computeSignature(payload, secret),
			secret:    "",
			wantErr:   true,
		},
		{
			name:      "invalid format no prefix",
			payload:   payload,
			signature: "md5=abcdef",
			secret:    secret,
			wantErr:   true,
		},
		{
			name:      "invalid hex",
			payload:   payload,
			signature: "sha256=notvalidhex",
			secret:    secret,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifySignature(tt.payload, tt.signature, tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifySignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
