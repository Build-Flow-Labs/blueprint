package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// VerifySignature validates the GitHub webhook HMAC-SHA256 signature.
// The signature header has format "sha256=<hex digest>".
func VerifySignature(payload []byte, signature, secret string) error {
	if secret == "" {
		return fmt.Errorf("webhook secret is empty")
	}
	if signature == "" {
		return fmt.Errorf("signature header is empty")
	}

	parts := strings.SplitN(signature, "=", 2)
	if len(parts) != 2 || parts[0] != "sha256" {
		return fmt.Errorf("invalid signature format: expected sha256=<hex>")
	}

	sigBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := mac.Sum(nil)

	if !hmac.Equal(sigBytes, expected) {
		return fmt.Errorf("signature mismatch")
	}

	return nil
}
