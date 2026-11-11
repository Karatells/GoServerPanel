// Package pki: встроенный Удостоверяющий Центр (Root CA) на crypto/x509.
// Корневой ключ хранится в DataDir/pki/ca.key (0600). Доменные сертификаты выпускаются
// через CSR → подпись корневым ключом; поддерживается отзыв и CRL.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"goserverpanel/internal/nginx"
	"goserverpanel/internal/store"
)

type PKI struct {
	dir string
	mu  sync.Mutex
}

type CAInfo struct {
	Exists      bool      `json:"exists"`
	Subject     string    `json:"subject,omitempty"`
	NotBefore   time.Time `json:"not_before,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
}

func New(dataDir string) *PKI { return &PKI{dir: filepath.Join(dataDir, "pki")} }

func (p *PKI) caCertPath() string { return filepath.Join(p.dir, "ca.crt") }
func (p *PKI) caKeyPath() string  { return filepath.Join(p.dir, "ca.key") }

func (p *PKI) HasCA() bool {
	_, e1 := os.Stat(p.caCertPath())
	_, e2 := os.Stat(p.caKeyPath())
	return e1 == nil && e2 == nil
}

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

// CreateCA генерирует самоподписанный корневой сертификат (RSA-4096). Повторно — ошибка.
func (p *PKI) CreateCA(cn, org string, years int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.HasCA() {
		return errors.New("корневой сертификат уже существует")
	}
	if cn == "" {
		cn = "GoServerPanel Root CA"
	}
	if len(cn) > 100 || len(org) > 100 {
		return errors.New("слишком длинное имя")
	}
	if years < 1 || years > 30 {
		years = 10
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	serial, err := randSerial()
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{org}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().AddDate(years, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		return err
	}
	if err := writePEM(p.caKeyPath(), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), 0o600); err != nil {
		return err
	}
	return writePEM(p.caCertPath(), "CERTIFICATE", der, 0o644)
}

func (p *PKI) loadCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	cb, err := os.ReadFile(p.caCertPath())
	if err != nil {
		return nil, nil, errors.New("корневой сертификат не создан")
	}
	kb, err := os.ReadFile(p.caKeyPath())
	if err != nil {
		return nil, nil, err
	}
	cblk, _ := pem.Decode(cb)
	kblk, _ := pem.Decode(kb)
	if cblk == nil || kblk == nil {
		return nil, nil, errors.New("повреждённые файлы CA")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(kblk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func (p *PKI) CACertPEM() ([]byte, error) {
	b, err := os.ReadFile(p.caCertPath())
	if err != nil {
		return nil, errors.New("корневой сертификат не создан")
	}
	return b, nil
}

func (p *PKI) Info() CAInfo {
	cert, _, err := p.loadCA()
	if err != nil {
		return CAInfo{}
	}
	return CAInfo{Exists: true, Subject: cert.Subject.String(), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, Fingerprint: fingerprint(cert.Raw)}
}

func fingerprint(der []byte) string {
	// SHA-256 в виде AA:BB:…
	h := sha256Sum(der)
	parts := make([]string, len(h))
	for i, b := range h {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// Issue выпускает сертификат для домена (+SAN). Возвращает метаданные.
func (p *PKI) Issue(domain string, sans []string, days int) (store.CertMeta, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var meta store.CertMeta
	caCert, caKey, err := p.loadCA()
	if err != nil {
		return meta, err
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !nginx.DomainRe.MatchString(domain) && net.ParseIP(domain) == nil {
		return meta, fmt.Errorf("некорректное имя %q", domain)
	}
	if days < 1 || days > 825 {
		days = 397
	}
	names := []string{domain}
	seen := map[string]bool{domain: true}
	for _, s := range sans {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || seen[s] {
			continue
		}
		if !nginx.DomainRe.MatchString(s) && net.ParseIP(s) == nil {
			return meta, fmt.Errorf("некорректное SAN %q", s)
		}
		seen[s] = true
		names = append(names, s)
	}
	if len(names) > 50 {
		return meta, errors.New("слишком много SAN")
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return meta, err
	}
	// CSR → подпись (CSR-шаг сохраняет модель «запрос → CA подписывает»).
	csrTpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: domain}}
	var ips []net.IP
	var dns []string
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, n)
		}
	}
	csrTpl.DNSNames, csrTpl.IPAddresses = dns, ips
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTpl, leafKey)
	if err != nil {
		return meta, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return meta, err
	}
	if err := csr.CheckSignature(); err != nil {
		return meta, err
	}
	serial, err := randSerial()
	if err != nil {
		return meta, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		return meta, err
	}
	hexSerial := serial.Text(16)
	dir := filepath.Join(p.dir, "issued", hexSerial)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return meta, err
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...)
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), chain, 0o644); err != nil {
		return meta, err
	}
	if err := writePEM(filepath.Join(dir, "key.pem"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(leafKey), 0o600); err != nil {
		return meta, err
	}
	return store.CertMeta{Serial: hexSerial, Domain: domain, SANs: names, NotBefore: tpl.NotBefore, NotAfter: tpl.NotAfter}, nil
}

// Paths возвращает пути к цепочке и ключу выпущенного сертификата.
func (p *PKI) Paths(serial string) (cert, key string, ok bool) {
	if !isHex(serial) {
		return "", "", false
	}
	d := filepath.Join(p.dir, "issued", serial)
	cert, key = filepath.Join(d, "fullchain.pem"), filepath.Join(d, "key.pem")
	_, e1 := os.Stat(cert)
	_, e2 := os.Stat(key)
	return cert, key, e1 == nil && e2 == nil
}

func (p *PKI) RemoveFiles(serial string) error {
	if !isHex(serial) {
		return errors.New("некорректный серийный номер")
	}
	return os.RemoveAll(filepath.Join(p.dir, "issued", serial))
}

// CRL формирует список отозванных сертификатов, подписанный корневым ключом.
func (p *PKI) CRL(certs []store.CertMeta) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	caCert, caKey, err := p.loadCA()
	if err != nil {
		return nil, err
	}
	var entries []x509.RevocationListEntry
	for _, c := range certs {
		if !c.Revoked {
			continue
		}
		n, ok := new(big.Int).SetString(c.Serial, 16)
		if !ok {
			continue
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: n, RevocationTime: c.RevokedAt})
	}
	now := time.Now()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now,
		NextUpdate:                now.AddDate(0, 0, 30),
		RevokedCertificateEntries: entries,
	}, caCert, caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}

func isHex(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// SelfSigned создаёт самоподписанный сертификат для HTTPS самой панели (ECDSA P-256).
func SelfSigned(certPath, keyPath string, hosts []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randSerial()
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "GoServerPanel", Organization: []string{"GoServerPanel (self-signed)"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if h != "" {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	if err := writePEM(keyPath, "EC PRIVATE KEY", kd, 0o600); err != nil {
		return err
	}
	return writePEM(certPath, "CERTIFICATE", der, 0o644)
}
