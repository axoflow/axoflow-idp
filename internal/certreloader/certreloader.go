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
	"crypto/tls"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Reloader serves the certificate in certFile and keyFile. It reloads both
// files when certFile changes, so a renewed certificate is served without a
// restart.
type Reloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	modTime time.Time
	cert    *tls.Certificate
}

func New(certFile, keyFile string) (*Reloader, error) {
	r := &Reloader{certFile: certFile, keyFile: keyFile}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// GetCertificate is a tls.Config.GetCertificate callback. If a reload fails,
// it keeps serving the previous certificate.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.reload(); err != nil {
		slog.Warn("failed to reload TLS certificate", "error", err)
	}
	return r.cert, nil
}

func (r *Reloader) reload() error {
	info, err := os.Stat(r.certFile)
	if err != nil {
		return err
	}
	if info.ModTime().Equal(r.modTime) {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.cert, r.modTime = &cert, info.ModTime()
	return nil
}
