package auth

import (
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct horse", h) || VerifyPassword("wrong", h) || VerifyPassword("x", "garbage") {
		t.Fatal("password verification broken")
	}
}

func TestJWT(t *testing.T) {
	sec := []byte("secret")
	tok := SignJWT(sec, Claims{Sub: "1", Exp: time.Now().Add(time.Minute).Unix()})
	if c, err := VerifyJWT(sec, tok); err != nil || c.Sub != "1" {
		t.Fatalf("verify: %v", err)
	}
	if _, err := VerifyJWT([]byte("other"), tok); err == nil {
		t.Fatal("accepted wrong secret")
	}
	if _, err := VerifyJWT(sec, SignJWT(sec, Claims{Exp: time.Now().Add(-time.Second).Unix()})); err == nil {
		t.Fatal("accepted expired token")
	}
	if _, err := VerifyJWT(sec, "eyJhbGciOiJub25lIn0.e30."); err == nil {
		t.Fatal("accepted alg=none")
	}
}

// Тестовый вектор RFC 6238 (SHA-1): секрет "12345678901234567890", T=59 → 94287082 (6 цифр: 287082).
func TestTOTPRFC6238(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	got, err := TOTPCode(secret, time.Unix(59, 0))
	if err != nil || got != "287082" {
		t.Fatalf("got %q err %v", got, err)
	}
	if !VerifyTOTP(secret, "287082", time.Unix(59+30, 0)) {
		t.Fatal("±1 window should be accepted")
	}
	if VerifyTOTP(secret, "287082", time.Unix(59+120, 0)) {
		t.Fatal("stale code accepted")
	}
}
