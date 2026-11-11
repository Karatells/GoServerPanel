package pki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"goserverpanel/internal/store"
)

func TestCAIssueAndRevoke(t *testing.T) {
	p := New(t.TempDir())
	if p.HasCA() {
		t.Fatal("CA must not exist yet")
	}
	if err := p.CreateCA("Test CA", "Org", 5); err != nil {
		t.Fatal(err)
	}
	if err := p.CreateCA("again", "", 5); err == nil {
		t.Fatal("second CA creation must fail")
	}
	meta, err := p.Issue("dev.local", []string{"www.dev.local", "127.0.0.1"}, 30)
	if err != nil {
		t.Fatal(err)
	}
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
	caPEM, _ := p.CACertPEM()
	cb, _ := pem.Decode(caPEM)
	ca, _ := x509.ParseCertificate(cb.Bytes)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "www.dev.local", Roots: pool, CurrentTime: time.Now()}); err != nil {
		t.Fatalf("leaf does not verify against CA: %v", err)
	}
	if len(rest) == 0 {
		t.Error("fullchain should include the CA certificate")
	}
	if len(leaf.IPAddresses) != 1 {
		t.Error("IP SAN missing")
	}
	meta.Revoked, meta.RevokedAt = true, time.Now()
	crlPEM, err := p.CRL([]store.CertMeta{meta})
	if err != nil {
		t.Fatal(err)
	}
	crlBlk, _ := pem.Decode(crlPEM)
	crl, err := x509.ParseRevocationList(crlBlk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("CRL signature: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatal("revoked serial not in CRL")
	}
}
