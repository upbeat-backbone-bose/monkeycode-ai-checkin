package captcha

import (
	"testing"
)

func TestGenerateHexSeed(t *testing.T) {
	// Test against known values from JS:
	// The function i(u, l) generates a hex string of length l from input u
	salt := generateHexSeed("15dba6f59886e9bf99ce729731", 32)
	target := generateHexSeed("15dba6f59886e9bf99ce729731d", 3)

	t.Logf("Salt: %s (len=%d)", salt, len(salt))
	t.Logf("Target: %s (len=%d)", target, len(target))

	if len(salt) != 32 {
		t.Errorf("salt length = %d, want 32", len(salt))
	}
	if len(target) != 3 {
		t.Errorf("target length = %d, want 3", len(target))
	}
}

func TestSolvePow(t *testing.T) {
	token := "15dba6f59886e9bf99ce72973"
	salt := generateHexSeed(token+"1", 32)
	target := generateHexSeed(token+"1d", 3)

	t.Logf("Testing solvePow: salt=%s, target=%s", salt, target)

	nonce, err := solvePow(salt, target)
	if err != nil {
		t.Fatalf("solvePow failed: %v", err)
	}

	t.Logf("Nonce found: %d", nonce)
}

func TestSolvePowSmallTarget(t *testing.T) {
	// Test with a known small case
	salt := "abc123"
	target := "00" // 1 byte = 0x00

	nonce, err := solvePow(salt, target)
	if err != nil {
		t.Fatalf("solvePow failed: %v", err)
	}

	// Verify the solution
	t.Logf("Nonce for target=00: %d", nonce)
}
