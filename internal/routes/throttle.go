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

package routes

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	attemptBurst    = 5                // sign-in attempts of a username that never wait
	attemptRefill   = 30 * time.Second // one more attempt per interval
	maxTrackedUsers = 10000
)

// limiter gives each username a bucket of attemptBurst sign-in attempts,
// refilled one per attemptRefill. A missing bucket is a full one.
type limiter struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets map[[sha256.Size]byte]bucket // by the SHA-256 of the username
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newLimiter() *limiter {
	return &limiter{now: time.Now, buckets: map[[sha256.Size]byte]bucket{}}
}

func (b bucket) tokensAt(now time.Time) float64 {
	return min(attemptBurst, b.tokens+float64(now.Sub(b.at))/float64(attemptRefill))
}

// take spends an attempt of username before its password is checked, so
// concurrent attempts count too, and returns how long to wait instead when
// none is left.
func (l *limiter) take(username string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now, key := l.now(), sha256.Sum256([]byte(username))
	tokens := float64(attemptBurst)
	if b, ok := l.buckets[key]; ok {
		tokens = b.tokensAt(now)
	}
	if tokens < 1 {
		return time.Duration((1 - tokens) * float64(attemptRefill))
	}
	if len(l.buckets) >= maxTrackedUsers {
		// Full buckets equal no bucket. If none is full, the fullest goes, so
		// a username whose attempts are used up keeps its bucket.
		var fullest [sha256.Size]byte
		most := -1.0
		for k, b := range l.buckets {
			if t := b.tokensAt(now); t >= attemptBurst {
				delete(l.buckets, k)
			} else if t > most {
				fullest, most = k, t
			}
		}
		if len(l.buckets) >= maxTrackedUsers {
			delete(l.buckets, fullest)
		}
	}
	l.buckets[key] = bucket{tokens: tokens - 1, at: now}
	if tokens < 2 {
		slog.Warn("sign-in attempts of a username used up", "username", username[:min(len(username), 64)])
	}
	return 0
}

// Rounded up, so a client that retries at Retry-After never lands before the
// wait ends.
func setRetryAfter(res http.ResponseWriter, wait time.Duration) {
	res.Header().Set("Retry-After", strconv.Itoa(int((wait+time.Second-1)/time.Second)))
}

// deviceToken marks a browser that signed in as username, so its sign-ins
// skip the limiter and nobody else can keep the owner out by using up the
// attempts. It is valid until the signing key changes.
func (r *Routes) deviceToken(username string) string {
	mac := hmac.New(sha256.New, r.deviceKey)
	mac.Write([]byte("device\x00" + username))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (r *Routes) knownDevice(req *http.Request, username string) bool {
	c, err := req.Cookie("device")
	return err == nil && hmac.Equal([]byte(c.Value), []byte(r.deviceToken(username)))
}

func (r *Routes) setDeviceCookie(res http.ResponseWriter, username string) {
	http.SetCookie(res, &http.Cookie{
		Name:     "device",
		Value:    r.deviceToken(username),
		MaxAge:   int((365 * 24 * time.Hour).Seconds()),
		Path:     r.url("/"),
		HttpOnly: true,
		Secure:   r.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}
