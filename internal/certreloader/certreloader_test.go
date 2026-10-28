// Copyright © 2026 Axoflow
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certreloader

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCert writes a fresh self-signed certificate for localhost to dir and
// sets its mtime explicitly, so a rotation is detected regardless of the
// filesystem's timestamp resolution.
func writeCert(t *testing.T, dir string, serial int64, modTime time.Time) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.Chtimes(certFile, modTime, modTime); err != nil {
		t.Fatalf("set mtime: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func startTLSServer(t *testing.T, certs *Reloader) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{
		Handler:           http.NotFoundHandler(),
		TLSConfig:         &tls.Config{GetCertificate: certs.GetCertificate},
		ReadHeaderTimeout: time.Second,
	}
	go func() { _ = server.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = server.Close() })
	return ln.Addr().String()
}

func servedSerial(t *testing.T, addr string, roots *x509.CertPool) int64 {
	t.Helper()

	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots, ServerName: "localhost"})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer func() { _ = conn.Close() }()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

func newTestReloader(t *testing.T, dir string) *Reloader {
	t.Helper()

	certs, err := New(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return certs
}

func TestServesRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	roots := x509.NewCertPool()
	roots.AddCert(writeCert(t, dir, 1, now))
	addr := startTLSServer(t, newTestReloader(t, dir))

	if got := servedSerial(t, addr, roots); got != 1 {
		t.Fatalf("served serial %d before renewal, want 1", got)
	}

	roots.AddCert(writeCert(t, dir, 2, now.Add(time.Minute)))

	if got := servedSerial(t, addr, roots); got != 2 {
		t.Errorf("served serial %d after renewal, want 2", got)
	}
}

func TestKeepsPreviousCertificateWhenNewFilesDoNotLoad(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeCert(t, dir, 1, now)
	certs := newTestReloader(t, dir)

	certFile := filepath.Join(dir, "tls.crt")
	if err := os.WriteFile(certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.Chtimes(certFile, now.Add(time.Minute), now.Add(time.Minute)); err != nil {
		t.Fatalf("set mtime: %v", err)
	}

	cert, _ := certs.GetCertificate(nil)
	if cert == nil || cert.Leaf.SerialNumber.Int64() != 1 {
		t.Error("GetCertificate did not return the previous certificate")
	}
}
