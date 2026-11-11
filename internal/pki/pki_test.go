package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goserverpanel/internal/store"
)

type ext struct {
	certPEM, keyPEM string
	cert            *x509.Certificate
	key             crypto.Signer
}

// makeExternalCA генерирует «чужой» CA (как будто выпущен вне панели).
func makeExternalCA(t *testing.T, isCA bool, notAfter time.Time, sec1 bool) ext {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "External CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	var kpem []byte
	if sec1 {
		kd, _ := x509.MarshalECPrivateKey(key)
		kpem = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	} else {
		kd, _ := x509.MarshalPKCS8PrivateKey(key)
		kpem = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
	}
	return ext{certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), keyPEM: string(kpem), cert: cert, key: key}
}

func verifyLeaf(t *testing.T, p *PKI, meta store.CertMeta, caCert *x509.Certificate, dns string) *x509.Certificate {
	t.Helper()
	certPath, keyPath, ok := p.Paths(meta.Serial)
	if !ok {
		t.Fatal("issued files missing")
	}
	if st, _ := os.Stat(keyPath); st.Mode().Perm() != 0o600 {
		t.Errorf("key perms %v", st.Mode().Perm())
	}
	chain, _ := os.ReadFile(certPath)
	blk, rest := pem.Decode(chain)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: dns, Roots: pool}); err != nil {
		t.Fatalf("leaf does not verify against CA: %v", err)
	}
	if len(rest) == 0 {
		t.Error("fullchain should include the CA certificate")
	}
	return leaf
}

func TestCreateIssueRevoke(t *testing.T) {
	p := New(t.TempDir())
	if len(p.ListCAs()) != 0 {
		t.Fatal("no CA expected yet")
	}
	ca1, err := p.CreateCA("Первый", "Test CA", "Org", 5)
	if err != nil {
		t.Fatal(err)
	}
	if ca1.Imported || ca1.Name != "Первый" || !strings.HasPrefix(ca1.KeyType, "RSA") {
		t.Fatalf("bad info: %+v", ca1)
	}
	meta, err := p.Issue(ca1.ID, "dev.local", []string{"www.dev.local", "127.0.0.1"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	if meta.CAID != ca1.ID {
		t.Error("CertMeta must reference the issuing CA")
	}
	caPEM, _ := p.CACertPEM(ca1.ID)
	cb, _ := pem.Decode(caPEM)
	caCert, _ := x509.ParseCertificate(cb.Bytes)
	leaf := verifyLeaf(t, p, meta, caCert, "www.dev.local")
	if len(leaf.IPAddresses) != 1 {
		t.Error("IP SAN missing")
	}

	meta.Revoked, meta.RevokedAt = true, time.Now()
	crlPEM, err := p.CRL(ca1.ID, []store.CertMeta{meta})
	if err != nil {
		t.Fatal(err)
	}
	crlBlk, _ := pem.Decode(crlPEM)
	crl, err := x509.ParseRevocationList(crlBlk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("CRL signature: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatal("revoked serial not in CRL")
	}
	// CRL другого CA не должен содержать чужие сертификаты
	other := makeExternalCA(t, true, time.Now().AddDate(1, 0, 0), false)
	oi, err := p.ImportCA("Other", other.certPEM, other.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	otherCRL, err := p.CRL(oi.ID, []store.CertMeta{meta})
	if err != nil {
		t.Fatal(err)
	}
	ob, _ := pem.Decode(otherCRL)
	ocrl, _ := x509.ParseRevocationList(ob.Bytes)
	if len(ocrl.RevokedCertificateEntries) != 0 {
		t.Error("another CA's CRL must not list foreign serials")
	}
}

func TestImportExternalCA(t *testing.T) {
	p := New(t.TempDir())
	for _, sec1 := range []bool{false, true} { // PKCS#8 и SEC1
		e := makeExternalCA(t, true, time.Now().AddDate(2, 0, 0), sec1)
		info, err := p.ImportCA("Corp", e.certPEM, e.keyPEM)
		if err != nil {
			t.Fatalf("import (sec1=%v): %v", sec1, err)
		}
		if !info.Imported || !strings.HasPrefix(info.KeyType, "ECDSA") {
			t.Fatalf("bad info: %+v", info)
		}
		if st, err := os.Stat(filepath.Join(p.dir, "cas", info.ID, "ca.key")); err != nil || st.Mode().Perm() != 0o600 {
			t.Error("imported key must be stored with 0600")
		}
		meta, err := p.Issue(info.ID, "intra.corp", nil, 10000) // срок обрезается до 397 дней
		if err != nil {
			t.Fatal(err)
		}
		leaf := verifyLeaf(t, p, meta, e.cert, "intra.corp")
		if leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 {
			t.Errorf("leaf must be signed by the ECDSA CA, got %v", leaf.SignatureAlgorithm)
		}
		if _, err := p.ImportCA("dup", e.certPEM, e.keyPEM); err == nil {
			t.Error("importing the same CA twice must fail")
		}
		if err := p.DeleteCA(info.ID); err != nil {
			t.Fatal(err)
		}
	}
	if len(p.ListCAs()) != 0 {
		t.Error("all CAs should be deleted")
	}
}

func TestImportRejects(t *testing.T) {
	p := New(t.TempDir())
	good := makeExternalCA(t, true, time.Now().AddDate(1, 0, 0), false)
	notCA := makeExternalCA(t, false, time.Now().AddDate(1, 0, 0), false)
	expired := makeExternalCA(t, true, time.Now().Add(-time.Minute), false)
	other := makeExternalCA(t, true, time.Now().AddDate(1, 0, 0), false)
	encrypted := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"

	cases := []struct{ name, cert, key, want string }{
		{"not a CA", notCA.certPEM, notCA.keyPEM, "не сертификат CA"},
		{"expired", expired.certPEM, expired.keyPEM, "истёк"},
		{"key mismatch", good.certPEM, other.keyPEM, "не соответствует"},
		{"encrypted key", good.certPEM, encrypted, "защищён паролем"},
		{"garbage cert", "hello", good.keyPEM, "CERTIFICATE"},
		{"garbage key", good.certPEM, "hello", "PEM"},
		{"huge", strings.Repeat("A", maxPEMSize+1), good.keyPEM, "слишком большой"},
	}
	for _, c := range cases {
		if _, err := p.ImportCA("x", c.cert, c.key); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", c.name, err, c.want)
		}
	}
	if len(p.ListCAs()) != 0 {
		t.Error("rejected imports must not leave files behind")
	}
	if _, err := p.ImportCA(strings.Repeat("n", 100), good.certPEM, good.keyPEM); err == nil {
		t.Error("overlong name must be rejected")
	}
}

// Единственный CA старых версий (pki/ca.crt, pki/ca.key) должен автоматически стать CA "default".
func TestLegacyMigration(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "pki")
	_ = os.MkdirAll(old, 0o700)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Legacy"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	_ = writePEM(filepath.Join(old, "ca.crt"), "CERTIFICATE", der, 0o644)
	_ = writePEM(filepath.Join(old, "ca.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), 0o600) // старый формат PKCS#1

	p := New(dir)
	cas := p.ListCAs()
	if len(cas) != 1 || cas[0].ID != LegacyCAID {
		t.Fatalf("legacy CA not migrated: %+v", cas)
	}
	if _, err := os.Stat(filepath.Join(old, "ca.crt")); err == nil {
		t.Error("old files should have been moved")
	}
	meta, err := p.Issue(LegacyCAID, "old.local", nil, 30)
	if err != nil {
		t.Fatalf("issue with migrated CA: %v", err)
	}
	if CAOf(store.CertMeta{}) != LegacyCAID || meta.CAID != LegacyCAID {
		t.Error("certificates without CAID must map to the legacy CA")
	}
	if _, err := p.CRL(LegacyCAID, nil); err != nil {
		t.Errorf("CRL for migrated CA: %v", err)
	}
}

func TestBadCAID(t *testing.T) {
	p := New(t.TempDir())
	for _, id := range []string{"../etc", "", "A B", strings.Repeat("a", 40)} {
		if _, err := p.CACertPEM(id); err == nil {
			t.Errorf("id %q must be rejected", id)
		}
		if err := p.DeleteCA(id); err == nil {
			t.Errorf("delete id %q must be rejected", id)
		}
	}
}
