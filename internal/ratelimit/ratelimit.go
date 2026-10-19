// Package ratelimit is brute-force protection: it counts *failures* per key
// (an IP, a client id) inside a window and refuses further attempts once a
// limit is hit. Successful requests are never throttled here; API Gateway
// stage throttling caps raw volume.
package ratelimit

import (
	"context"
	"log/slog"
	"time"

	"github.com/nathanblatter/squawk/internal/store"
)

// Policy is a limit over a window.
type Policy struct {
	Limit  int
	Window time.Duration
}

// Policies for each protected surface. Numbers are deliberately generous for
// humans and hopeless for guessing 256-bit secrets.
var (
	// TokenIP: failed credential exchanges from one IP.
	TokenIP = Policy{Limit: 30, Window: 10 * time.Minute}
	// TokenClient: failed exchanges against one service id, from anywhere.
	// Hitting it locks that service's token endpoint for the window.
	TokenClient = Policy{Limit: 10, Window: 15 * time.Minute}
	// LoginIP: failed passkey sign-ins or registrations from one IP.
	LoginIP = Policy{Limit: 20, Window: 10 * time.Minute}
	// LoginUser: wrong passwords against one username, from anywhere.
	LoginUser = Policy{Limit: 10, Window: 15 * time.Minute}
	// EmailSend: sign-in / verification codes sent to one address. Counts
	// sends, not failures: it caps how much mail a stranger can trigger.
	EmailSend = Policy{Limit: 5, Window: 15 * time.Minute}
	// EmailSendIP: codes requested from one IP, any address.
	EmailSendIP = Policy{Limit: 20, Window: 15 * time.Minute}
	// LoginAlert: new-sign-in alert emails to one account. Counts sends.
	LoginAlert = Policy{Limit: 3, Window: 24 * time.Hour}
)

// Limiter checks and records failures through the store.
type Limiter struct {
	Store store.Store
	Now   func() time.Time
	Log   *slog.Logger
}

// New builds a limiter.
func New(st store.Store) *Limiter {
	return &Limiter{Store: st, Now: time.Now, Log: slog.Default()}
}

// Allow reports whether key is still under its policy's limit. Store errors
// fail open (logged): an outage must not lock everyone out, and the store
// being down means nothing else works either.
func (l *Limiter) Allow(ctx context.Context, p Policy, key string) bool {
	n, err := l.Store.FailureCount(ctx, key, l.Now())
	if err != nil {
		l.Log.Error("ratelimit read failed", "key", key, "err", err)
		return true
	}
	return n < p.Limit
}

// Fail records one failure for key.
func (l *Limiter) Fail(ctx context.Context, p Policy, key string) {
	if _, err := l.Store.RecordFailure(ctx, key, l.Now(), p.Window); err != nil {
		l.Log.Error("ratelimit write failed", "key", key, "err", err)
	}
}

// RetryAfter is the conservative Retry-After to advertise for a policy.
func (p Policy) RetryAfter() int { return int(p.Window.Seconds()) }
