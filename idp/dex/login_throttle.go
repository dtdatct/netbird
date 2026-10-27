package dex

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/netbirdio/netbird/trustedproxy"
)

// Login throttling for the embedded IdP's local (email/password) connector.
//
// The embedded Dex plane is served from its own handler and never passes
// through the management API middleware, so it carries none of the API rate
// limiting. Without a limiter here the local login form accepts an unbounded
// number of password guesses (see Cyber finding F-0002 / CWE-307).
//
// Two independent controls are applied, both keyed on *failed* attempts only so
// that a user who signs in successfully is never penalised:
//
//   - Per account: a temporary lockout after a number of consecutive failures
//     for the same submitted login. This is the primary defence, because it
//     bounds the guessing budget against a specific account no matter how many
//     source addresses are used.
//   - Per source address: a failure budget so that a single peer cannot spray
//     many accounts. It only draws down on failures, so shared egress
//     addresses (a proxy in front of the deployment) are not throttled for
//     ordinary sign-ins.
//
// Neither control changes the response body for a wrong password, so the
// existing protection against account enumeration is preserved.

const (
	defaultLoginAttemptsPerMinute = 30
	defaultLoginAttemptsBurst     = 30
	defaultAccountFailureLimit    = 10
	defaultAccountLockout         = 1 * time.Minute
	defaultMaxAccountLockout      = 15 * time.Minute
	defaultLoginEntryTTL          = 30 * time.Minute
	defaultLoginMaxEntries        = 10000
)

// LoginThrottleConfig configures the local login throttle. A zero value is
// replaced by the defaults, so callers can override only what they care about.
type LoginThrottleConfig struct {
	// AttemptsPerMinute is the sustained failure budget per source address.
	AttemptsPerMinute float64
	// AttemptsBurst is the number of failures from one source address that may
	// be tolerated back to back.
	AttemptsBurst int
	// AccountFailureLimit is the number of consecutive failures for the same
	// submitted login before it is temporarily locked out.
	AccountFailureLimit int
	// AccountLockout is the first lockout duration. It grows for a login that
	// keeps failing after each lockout expires, up to MaxAccountLockout.
	AccountLockout time.Duration
	// MaxAccountLockout caps the escalating lockout duration.
	MaxAccountLockout time.Duration
	// EntryTTL is how long an idle tracking entry is kept.
	EntryTTL time.Duration
	// MaxEntries bounds the number of tracked accounts, so that a flood of
	// distinct login values cannot grow the map without limit.
	MaxEntries int
	// TrustedProxies lists upstream proxies whose forwarding headers may be
	// believed when resolving the client address. Empty means the direct peer
	// address is used.
	TrustedProxies *trustedproxy.List
}

func (c LoginThrottleConfig) withDefaults() LoginThrottleConfig {
	if c.AttemptsPerMinute <= 0 {
		c.AttemptsPerMinute = defaultLoginAttemptsPerMinute
	}
	if c.AttemptsBurst <= 0 {
		c.AttemptsBurst = defaultLoginAttemptsBurst
	}
	if c.AccountFailureLimit <= 0 {
		c.AccountFailureLimit = defaultAccountFailureLimit
	}
	if c.AccountLockout <= 0 {
		c.AccountLockout = defaultAccountLockout
	}
	if c.MaxAccountLockout < c.AccountLockout {
		c.MaxAccountLockout = defaultMaxAccountLockout
		if c.MaxAccountLockout < c.AccountLockout {
			c.MaxAccountLockout = c.AccountLockout
		}
	}
	if c.EntryTTL <= 0 {
		c.EntryTTL = defaultLoginEntryTTL
	}
	if c.MaxEntries <= 0 {
		c.MaxEntries = defaultLoginMaxEntries
	}
	return c
}

type loginAccountEntry struct {
	consecutiveFailures int
	strikes             int
	lockedUntil         time.Time
	lastSeen            time.Time
}

type loginIPEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// LoginThrottle bounds password guessing against the embedded IdP's local
// connector. It is safe for concurrent use.
type LoginThrottle struct {
	cfg      LoginThrottleConfig
	mu       sync.Mutex
	accounts map[string]*loginAccountEntry
	ips      map[string]*loginIPEntry
	now      func() time.Time
	// lastCleanup rate-limits the O(n) pruning pass so that a steady stream of
	// login requests does not pay for a full map scan on every attempt.
	lastCleanup time.Time
}

// NewLoginThrottle creates a throttle. A nil config uses the defaults.
func NewLoginThrottle(cfg *LoginThrottleConfig) *LoginThrottle {
	resolved := LoginThrottleConfig{}
	if cfg != nil {
		resolved = *cfg
	}
	return &LoginThrottle{
		cfg:      resolved.withDefaults(),
		accounts: make(map[string]*loginAccountEntry),
		ips:      make(map[string]*loginIPEntry),
		now:      time.Now,
	}
}

// Check reports whether an attempt for account from clientIP may be processed.
// When it may not, retryAfter is a non-negative hint for the Retry-After header.
func (t *LoginThrottle) Check(clientIP, account string) (retryAfter time.Duration, allowed bool) {
	now := t.now()
	account = normalizeLogin(account)

	t.mu.Lock()
	defer t.mu.Unlock()

	t.cleanupLocked(now)

	if entry, ok := t.accounts[account]; ok {
		entry.lastSeen = now
		if now.Before(entry.lockedUntil) {
			return entry.lockedUntil.Sub(now), false
		}
	}

	if entry, ok := t.ips[clientIP]; ok {
		entry.lastSeen = now
		if entry.limiter.Tokens() < 1 {
			return t.ipRetryAfter(), false
		}
	}

	return 0, true
}

// RecordFailure registers a failed attempt for account from clientIP.
func (t *LoginThrottle) RecordFailure(clientIP, account string) {
	now := t.now()
	account = normalizeLogin(account)

	t.mu.Lock()
	defer t.mu.Unlock()

	t.cleanupLocked(now)

	entry, ok := t.accounts[account]
	if !ok {
		entry = &loginAccountEntry{}
		t.accounts[account] = entry
	}
	entry.lastSeen = now
	entry.consecutiveFailures++
	if entry.consecutiveFailures >= t.cfg.AccountFailureLimit {
		entry.consecutiveFailures = 0
		entry.lockedUntil = now.Add(t.lockoutFor(entry.strikes))
		entry.strikes++
	}

	ip, ok := t.ips[clientIP]
	if !ok {
		ip = &loginIPEntry{
			limiter: rate.NewLimiter(rate.Limit(t.cfg.AttemptsPerMinute/60.0), t.cfg.AttemptsBurst),
		}
		t.ips[clientIP] = ip
	}
	ip.lastSeen = now
	// Draw one token from the address budget; exhaustion is enforced by Check.
	_ = ip.limiter.Allow()
}

// RecordSuccess clears the consecutive failure state for account, so a
// legitimate sign-in restores the full guessing budget.
func (t *LoginThrottle) RecordSuccess(account string) {
	account = normalizeLogin(account)
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.accounts[account]
	if !ok {
		return
	}
	entry.consecutiveFailures = 0
	entry.strikes = 0
	entry.lockedUntil = time.Time{}
	entry.lastSeen = now
}

func (t *LoginThrottle) lockoutFor(strikes int) time.Duration {
	d := t.cfg.AccountLockout
	for i := 0; i < strikes && d < t.cfg.MaxAccountLockout; i++ {
		d *= 2
	}
	if d > t.cfg.MaxAccountLockout {
		d = t.cfg.MaxAccountLockout
	}
	return d
}

func (t *LoginThrottle) ipRetryAfter() time.Duration {
	seconds := t.cfg.AttemptsPerMinute / 60.0
	if seconds <= 0 {
		return time.Second
	}
	d := time.Duration(float64(time.Second) / seconds)
	if d < time.Second {
		d = time.Second
	}
	return d
}

// cleanupLocked drops idle entries and enforces the entry ceiling. It runs at
// most once per minute so the cost stays amortised.
func (t *LoginThrottle) cleanupLocked(now time.Time) {
	overAccounts := len(t.accounts) >= t.cfg.MaxEntries
	overIPs := len(t.ips) >= t.cfg.MaxEntries
	if !overAccounts && !overIPs && now.Sub(t.lastCleanup) < time.Minute {
		return
	}
	t.lastCleanup = now

	pruneAccounts(t.accounts, now, t.cfg.EntryTTL)
	pruneIPs(t.ips, now, t.cfg.EntryTTL)

	// A flood of distinct login values must not grow memory without limit, so
	// drop the least recently seen entries down to half the ceiling.
	evictOldestAccounts(t.accounts, t.cfg.MaxEntries/2)
	evictOldestIPs(t.ips, t.cfg.MaxEntries/2)
}

func pruneAccounts(entries map[string]*loginAccountEntry, now time.Time, ttl time.Duration) {
	for key, entry := range entries {
		if now.Sub(entry.lastSeen) > ttl && !now.Before(entry.lockedUntil) {
			delete(entries, key)
		}
	}
}

func pruneIPs(entries map[string]*loginIPEntry, now time.Time, ttl time.Duration) {
	for key, entry := range entries {
		if now.Sub(entry.lastSeen) > ttl {
			delete(entries, key)
		}
	}
}

// evictOldestAccounts keeps at most limit accounts, removing the least recently
// seen first.
func evictOldestAccounts(entries map[string]*loginAccountEntry, limit int) {
	if limit < 1 {
		limit = 1
	}
	for len(entries) > limit {
		var oldest string
		var oldestSeen time.Time
		for key, entry := range entries {
			if oldest == "" || entry.lastSeen.Before(oldestSeen) {
				oldest, oldestSeen = key, entry.lastSeen
			}
		}
		if oldest == "" {
			return
		}
		delete(entries, oldest)
	}
}

// evictOldestIPs keeps at most limit addresses, removing the least recently
// seen first.
func evictOldestIPs(entries map[string]*loginIPEntry, limit int) {
	if limit < 1 {
		limit = 1
	}
	for len(entries) > limit {
		var oldest string
		var oldestSeen time.Time
		for key, entry := range entries {
			if oldest == "" || entry.lastSeen.Before(oldestSeen) {
				oldest, oldestSeen = key, entry.lastSeen
			}
		}
		if oldest == "" {
			return
		}
		delete(entries, oldest)
	}
}

func normalizeLogin(account string) string {
	return strings.ToLower(strings.TrimSpace(account))
}

// loginAccountLogKey returns a stable, non-reversible key for an account so
// repeated failures can be correlated in operator alerts without writing the
// submitted email address to the logs.
func loginAccountLogKey(account string) string {
	sum := sha256.Sum256([]byte(normalizeLogin(account)))
	return hex.EncodeToString(sum[:8])
}

// clientIP resolves the source address for throttling, trusting forwarding
// headers only from configured proxies.
func (t *LoginThrottle) clientIP(r *http.Request) string {
	if trusted := t.cfg.TrustedProxies; !trusted.Empty() {
		if addr := trusted.ResolveClientIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For")); addr.IsValid() {
			return addr.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if r.RemoteAddr == "" {
			return "unknown"
		}
		return r.RemoteAddr
	}
	if host == "" {
		return "unknown"
	}
	return host
}

// isLocalLoginSubmission reports whether the request posts credentials to a
// connector login form (the local connector posts to /oauth2/auth/local/login).
func isLocalLoginSubmission(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	return strings.HasPrefix(path, "/oauth2/auth/") && strings.HasSuffix(path, "/login")
}

// statusRecorder captures the status code so the throttle can tell a rejected
// sign-in from an accepted one. Dex answers a wrong password with 401 and a
// successful local sign-in with a redirect.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// loginSucceeded reports whether the recorded response represents a completed
// sign-in.
func loginSucceeded(status int) bool {
	return status >= 300 && status < 400
}

func writeLoginThrottled(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(retryAfter.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte("Too many failed login attempts. Please try again later.\n"))
}
