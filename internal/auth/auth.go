// Package auth: хэширование паролей (PBKDF2-SHA256), JWT HS256, TOTP (RFC 6238).
// Реализовано на стандартной библиотеке — без внешних зависимостей.
package auth

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const pbkdf2Iter = 310000

func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iter,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func VerifyPassword(pw, enc string) bool {
	p := strings.Split(enc, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(p[1])
	if err != nil || iter < 1000 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(p[2])
	want, err2 := base64.RawStdEncoding.DecodeString(p[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// DummyVerify тратит время как реальная проверка (защита от перебора имён по таймингу).
func DummyVerify() {
	VerifyPassword("x", "pbkdf2-sha256$310000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
}

func RandomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

// ---- JWT ----

type Claims struct {
	Sub  string `json:"sub"`
	Name string `json:"name"`
	Role string `json:"role"`
	Exp  int64  `json:"exp"`
	JTI  string `json:"jti"`
}

var b64 = base64.RawURLEncoding

func SignJWT(secret []byte, c Claims) string {
	h := b64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	pl, _ := json.Marshal(c)
	body := h + "." + b64.EncodeToString(pl)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(body))
	return body + "." + b64.EncodeToString(m.Sum(nil))
}

var ErrToken = errors.New("invalid token")

func VerifyJWT(secret []byte, tok string) (Claims, error) {
	var c Claims
	p := strings.Split(tok, ".")
	if len(p) != 3 {
		return c, ErrToken
	}
	hdr, err := b64.DecodeString(p[0])
	if err != nil {
		return c, ErrToken
	}
	var h struct{ Alg string }
	if json.Unmarshal(hdr, &h) != nil || h.Alg != "HS256" {
		return c, ErrToken
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(p[0] + "." + p[1]))
	sig, err := b64.DecodeString(p[2])
	if err != nil || !hmac.Equal(sig, m.Sum(nil)) {
		return c, ErrToken
	}
	pl, err := b64.DecodeString(p[1])
	if err != nil || json.Unmarshal(pl, &c) != nil {
		return c, ErrToken
	}
	if time.Now().Unix() >= c.Exp {
		return c, errors.New("token expired")
	}
	return c, nil
}

// ---- TOTP ----

func NewTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func TOTPURI(issuer, user, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(issuer), url.PathEscape(user), secret, url.QueryEscape(issuer))
}

func totpAt(secret string, counter uint64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(buf[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code), nil
}

func TOTPCode(secret string, t time.Time) (string, error) {
	return totpAt(secret, uint64(t.Unix()/30))
}

// VerifyTOTP допускает дрейф часов ±1 шаг.
func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	base := uint64(now.Unix() / 30)
	for d := -1; d <= 1; d++ {
		c, err := totpAt(secret, uint64(int64(base)+int64(d)))
		if err == nil && subtle.ConstantTimeCompare([]byte(c), []byte(code)) == 1 {
			return true
		}
	}
	return false
}
