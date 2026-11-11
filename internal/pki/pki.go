// Package pki: встроенный Удостоверяющий Центр на crypto/x509.
//
// Поддерживается несколько корневых CA: созданных панелью (RSA-4096) и импортированных
// (свой сертификат + закрытый ключ; RSA, ECDSA, Ed25519). Каждый CA хранится в
// DataDir/pki/cas/<id>/{ca.crt,ca.key,meta.json}. Доменные сертификаты выпускаются
// через CSR → подпись выбранным CA; поддерживаются отзыв и CRL для каждого CA.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"goserverpanel/internal/nginx"
	"goserverpanel/internal/store"
)

const (
	// LegacyCAID — идентификатор CA, созданного версиями панели с единственным CA.
	LegacyCAID = "default"
	maxPEMSize = 64 << 10
)

var idRe = regexp.MustCompile(`^[a-z0-9]{1,32}$`)

type PKI struct {
	dir string
	mu  sync.Mutex
}

type CAInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Subject     string    `json:"subject"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`
	KeyType     string    `json:"key_type"`
	Imported    bool      `json:"imported"`
	Expired     bool      `json:"expired"`
}

type caMeta struct {
	Name     string    `json:"name"`
	Imported bool      `json:"imported"`
	Created  time.Time `json:"created"`
}

// CAOf возвращает идентификатор CA сертификата (пустой — устаревший единственный CA).
func CAOf(c store.CertMeta) string {
	if c.CAID == "" {
		return LegacyCAID
	}
	return c.CAID
}

func New(dataDir string) *PKI {
	p := &PKI{dir: filepath.Join(dataDir, "pki")}
	p.migrate()
	return p
}

// migrate переносит единственный CA старого формата (pki/ca.crt, pki/ca.key) в pki/cas/default.
func (p *PKI) migrate() {
	oldCert, oldKey := filepath.Join(p.dir, "ca.crt"), filepath.Join(p.dir, "ca.key")
	if _, err := os.Stat(oldCert); err != nil {
		return
	}
	dst := filepath.Join(p.dir, "cas", LegacyCAID)
	if _, err := os.Stat(dst); err == nil {
		return
	}
	if os.MkdirAll(dst, 0o700) != nil {
		return
	}
	if os.Rename(oldCert, filepath.Join(dst, "ca.crt")) != nil || os.Rename(oldKey, filepath.Join(dst, "ca.key")) != nil {
		return
	}
	p.writeMeta(dst, caMeta{Name: "Root CA", Created: time.Now()})
}

func (p *PKI) writeMeta(dir string, m caMeta) {
	b, _ := json.Marshal(m)
	_ = os.WriteFile(filepath.Join(dir, "meta.json"), b, 0o600)
}

func (p *PKI) caDir(id string) (string, error) {
	if !idRe.MatchString(id) {
		return "", errors.New("некорректный идентификатор CA")
	}
	return filepath.Join(p.dir, "cas", id), nil
}

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

func keyType(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return "unknown"
}

func infoOf(id string, m caMeta, cert *x509.Certificate) CAInfo {
	return CAInfo{
		ID: id, Name: m.Name, Subject: cert.Subject.String(), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		Fingerprint: fingerprint(cert.Raw), KeyType: keyType(cert.PublicKey), Imported: m.Imported, Expired: time.Now().After(cert.NotAfter),
	}
}

func (p *PKI) readMeta(dir string) caMeta {
	var m caMeta
	if b, err := os.ReadFile(filepath.Join(dir, "meta.json")); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	if m.Name == "" {
		m.Name = "Root CA"
	}
	return m
}

func readCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("повреждённый сертификат CA")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// parsePrivateKey разбирает PKCS#1 / PKCS#8 / SEC1 ключ из PEM. Зашифрованные ключи не поддерживаются.
func parsePrivateKey(data []byte) (crypto.Signer, error) {
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			return nil, errors.New("в файле ключа не найден PEM-блок закрытого ключа")
		}
		if strings.Contains(blk.Type, "ENCRYPTED") || blk.Headers["DEK-Info"] != "" {
			return nil, errors.New("ключ защищён паролем — снимите пароль (openssl pkey -in key.pem -out key-nopass.pem) и загрузите снова")
		}
		switch blk.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(blk.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(blk.Bytes)
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, err
			}
			s, ok := k.(crypto.Signer)
			if !ok {
				return nil, errors.New("неподдерживаемый тип ключа")
			}
			return s, nil
		}
	}
}

func (p *PKI) loadCA(id string) (*x509.Certificate, crypto.Signer, error) {
	dir, err := p.caDir(id)
	if err != nil {
		return nil, nil, err
	}
	cert, err := readCert(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, nil, errors.New("CA не найден")
	}
	kb, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, nil, err
	}
	key, err := parsePrivateKey(kb)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// ListCAs возвращает все корневые сертификаты, отсортированные по имени.
func (p *PKI) ListCAs() []CAInfo {
	out := []CAInfo{}
	ents, _ := os.ReadDir(filepath.Join(p.dir, "cas"))
	for _, e := range ents {
		if !e.IsDir() || !idRe.MatchString(e.Name()) {
			continue
		}
		dir := filepath.Join(p.dir, "cas", e.Name())
		cert, err := readCert(filepath.Join(dir, "ca.crt"))
		if err != nil {
			continue
		}
		out = append(out, infoOf(e.Name(), p.readMeta(dir), cert))
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func (p *PKI) Info(id string) (CAInfo, error) {
	dir, err := p.caDir(id)
	if err != nil {
		return CAInfo{}, err
	}
	cert, err := readCert(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return CAInfo{}, errors.New("CA не найден")
	}
	return infoOf(id, p.readMeta(dir), cert), nil
}

func cleanName(name, fallback string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = fallback
	}
	if len(name) > 80 || strings.ContainsAny(name, "\n\r\t") {
		return "", errors.New("некорректное название CA (до 80 символов)")
	}
	return name, nil
}

func (p *PKI) newCADir() (id, dir string, err error) {
	id = store.NewID()
	dir = filepath.Join(p.dir, "cas", id)
	err = os.MkdirAll(dir, 0o700)
	return
}

// CreateCA генерирует самоподписанный корневой сертификат (RSA-4096).
func (p *PKI) CreateCA(name, cn, org string, years int) (CAInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	name, err := cleanName(name, "Root CA")
	if err != nil {
		return CAInfo{}, err
	}
	if cn == "" {
		cn = name
	}
	if len(cn) > 100 || len(org) > 100 {
		return CAInfo{}, errors.New("слишком длинное имя")
	}
	if years < 1 || years > 30 {
		years = 10
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return CAInfo{}, err
	}
	serial, err := randSerial()
	if err != nil {
		return CAInfo{}, err
	}
	subj := pkix.Name{CommonName: cn}
	if org != "" {
		subj.Organization = []string{org}
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subj,
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().AddDate(years, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return CAInfo{}, err
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return CAInfo{}, err
	}
	id, dir, err := p.newCADir()
	if err != nil {
		return CAInfo{}, err
	}
	if err := writePEM(filepath.Join(dir, "ca.key"), "PRIVATE KEY", kd, 0o600); err != nil {
		return CAInfo{}, err
	}
	if err := writePEM(filepath.Join(dir, "ca.crt"), "CERTIFICATE", der, 0o644); err != nil {
		return CAInfo{}, err
	}
	p.writeMeta(dir, caMeta{Name: name, Created: time.Now()})
	return p.Info(id)
}

// ImportCA добавляет собственный корневой сертификат вместе с закрытым ключом.
// Проверяется: сертификат — CA, не просрочен, ключ расшифрован и соответствует сертификату.
func (p *PKI) ImportCA(name, certPEM, keyPEM string) (CAInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	name, err := cleanName(name, "Imported CA")
	if err != nil {
		return CAInfo{}, err
	}
	if len(certPEM) > maxPEMSize || len(keyPEM) > maxPEMSize {
		return CAInfo{}, errors.New("файл слишком большой")
	}
	var cert *x509.Certificate
	rest := []byte(certPEM)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			if cert, err = x509.ParseCertificate(blk.Bytes); err != nil {
				return CAInfo{}, fmt.Errorf("не удалось разобрать сертификат: %w", err)
			}
			break
		}
	}
	if cert == nil {
		return CAInfo{}, errors.New("в сертификате не найден PEM-блок CERTIFICATE")
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return CAInfo{}, errors.New("это не сертификат CA (в нём нет basicConstraints: CA:TRUE)")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return CAInfo{}, errors.New("сертификату запрещено подписывать другие сертификаты (keyUsage без keyCertSign)")
	}
	if time.Now().After(cert.NotAfter) {
		return CAInfo{}, errors.New("срок действия сертификата истёк")
	}
	key, err := parsePrivateKey([]byte(keyPEM))
	if err != nil {
		return CAInfo{}, err
	}
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return CAInfo{}, errors.New("закрытый ключ не соответствует сертификату")
	}
	fp := fingerprint(cert.Raw)
	for _, c := range p.ListCAs() {
		if c.Fingerprint == fp {
			return CAInfo{}, fmt.Errorf("этот сертификат уже добавлен как «%s»", c.Name)
		}
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return CAInfo{}, err
	}
	id, dir, err := p.newCADir()
	if err != nil {
		return CAInfo{}, err
	}
	if err := writePEM(filepath.Join(dir, "ca.key"), "PRIVATE KEY", kd, 0o600); err != nil {
		os.RemoveAll(dir)
		return CAInfo{}, err
	}
	if err := writePEM(filepath.Join(dir, "ca.crt"), "CERTIFICATE", cert.Raw, 0o644); err != nil {
		os.RemoveAll(dir)
		return CAInfo{}, err
	}
	p.writeMeta(dir, caMeta{Name: name, Imported: true, Created: time.Now()})
	return p.Info(id)
}

// DeleteCA удаляет CA вместе с его закрытым ключом (проверка зависимых сертификатов — на вызывающей стороне).
func (p *PKI) DeleteCA(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	dir, err := p.caDir(id)
	if err != nil {
		return err
	}
	if _, err := os.Stat(dir); err != nil {
		return errors.New("CA не найден")
	}
	return os.RemoveAll(dir)
}

func (p *PKI) CACertPEM(id string) ([]byte, error) {
	dir, err := p.caDir(id)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, errors.New("CA не найден")
	}
	return b, nil
}

func fingerprint(der []byte) string {
	h := sha256Sum(der)
	parts := make([]string, len(h))
	for i, b := range h {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// Issue выпускает сертификат для домена (+SAN), подписанный выбранным CA.
func (p *PKI) Issue(caID, domain string, sans []string, days int) (store.CertMeta, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var meta store.CertMeta
	caCert, caKey, err := p.loadCA(caID)
	if err != nil {
		return meta, err
	}
	now := time.Now()
	if now.After(caCert.NotAfter) {
		return meta, errors.New("срок действия выбранного CA истёк")
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
	var ips []net.IP
	var dns []string
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, n)
		}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: domain}, DNSNames: dns, IPAddresses: ips,
	}, leafKey)
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
	notAfter := now.AddDate(0, 0, days)
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter // сертификат не может жить дольше CA
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
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
	return store.CertMeta{Serial: hexSerial, CAID: caID, Domain: domain, SANs: names, NotBefore: tpl.NotBefore, NotAfter: tpl.NotAfter}, nil
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

// CRL формирует список отозванных сертификатов выбранного CA, подписанный его ключом.
func (p *PKI) CRL(caID string, certs []store.CertMeta) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	caCert, caKey, err := p.loadCA(caID)
	if err != nil {
		return nil, err
	}
	if caCert.KeyUsage != 0 && caCert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, errors.New("сертификат этого CA не разрешает подпись CRL (keyUsage без cRLSign)")
	}
	var entries []x509.RevocationListEntry
	for _, c := range certs {
		if !c.Revoked || CAOf(c) != caID {
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
