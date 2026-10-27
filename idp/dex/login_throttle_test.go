package dex

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/trustedproxy"
)

func newThrottle(t *testing.T, cfg *LoginThrottleConfig) *LoginThrottle {
	t.Helper()
	throttle := NewLoginThrottle(cfg)
	require.NotNil(t, throttle)
	return throttle
}

// TestLoginThrottle_LocksAccountAfterRepeatedFailures covers the primary
// control: an account is locked out after N consecutive failures even when the
// attempts come from rotating source addresses, so spreading the attack across
// IPs does not reset the budget.
func TestLoginThrottle_LocksAccountAfterRepeatedFailures(t *testing.T) {
	throttle := newThrottle(t, &LoginThrottleConfig{
		AccountFailureLimit: 3,
		AccountLockout:      time.Minute,
		MaxAccountLockout:   time.Minute,
	})

	for i := 0; i < 3; i++ {
		_, allowed := throttle.Check("203.0.113."+string(rune('1'+i)), "victim@example.com")
		require.True(t, allowed, "attempt %d must be allowed before the lockout", i+1)
		throttle.RecordFailure("203.0.113."+string(rune('1'+i)), "victim@example.com")
	}

	retryAfter, allowed := throttle.Check("198.51.100.7", "victim@example.com")
	assert.False(t, allowed, "a fresh source address must not bypass an account lockout")
	assert.Positive(t, retryAfter)

	// A different account is unaffected.
	_, allowed = throttle.Check("198.51.100.7", "other@example.com")
	assert.True(t, allowed)
}

// TestLoginThrottle_SuccessResetsAccountStreak ensures a legitimate sign-in
// restores the guess budget rather than leaving a live user one typo from a
// lockout.
func TestLoginThrottle_SuccessResetsAccountStreak(t *testing.T) {
	throttle := newThrottle(t, &LoginThrottleConfig{AccountFailureLimit: 3, AccountLockout: time.Minute})

	const account = "user@example.com"
	throttle.RecordFailure("203.0.113.1", account)
	throttle.RecordFailure("203.0.113.1", account)
	throttle.RecordSuccess(account)

	for i := 0; i < 3; i++ {
		_, allowed := throttle.Check("203.0.113.1", account)
		require.True(t, allowed)
		throttle.RecordFailure("203.0.113.1", account)
	}

	_, allowed := throttle.Check("203.0.113.1", account)
	assert.False(t, allowed, "the streak must be counted again from zero after a success")
}

// TestLoginThrottle_LockoutEscalates verifies that a login that keeps failing
// after its lockout expires is locked out for longer.
func TestLoginThrottle_LockoutEscalates(t *testing.T) {
	throttle := newThrottle(t, &LoginThrottleConfig{
		AccountFailureLimit: 2,
		AccountLockout:      10 * time.Second,
		MaxAccountLockout:   time.Minute,
	})

	const account = "escalate@example.com"
	now := time.Now()
	throttle.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		throttle.RecordFailure("203.0.113.5", account)
	}
	first, allowed := throttle.Check("203.0.113.5", account)
	require.False(t, allowed)
	assert.InDelta(t, float64(10*time.Second), float64(first), float64(time.Second))

	now = now.Add(11 * time.Second)
	_, allowed = throttle.Check("203.0.113.5", account)
	require.True(t, allowed, "the lockout must expire")

	for i := 0; i < 2; i++ {
		throttle.RecordFailure("203.0.113.5", account)
	}
	second, allowed := throttle.Check("203.0.113.5", account)
	require.False(t, allowed)
	assert.Greater(t, second, first, "a repeated offender must be locked out for longer")
}

// TestLoginThrottle_AddressBudgetDrawsDownOnFailures covers the secondary
// control: one address cannot spray many accounts, while a source address that
// is only ever successful is never throttled (shared proxy egress must keep
// working).
func TestLoginThrottle_AddressBudgetDrawsDownOnFailures(t *testing.T) {
	const ip = "203.0.113.9"

	spray := newThrottle(t, &LoginThrottleConfig{
		AttemptsPerMinute: 1,
		AttemptsBurst:     3,
		// A very high account limit isolates the address budget.
		AccountFailureLimit: 10000,
	})
	for i := 0; i < 3; i++ {
		_, allowed := spray.Check(ip, "target"+string(rune('a'+i))+"@example.com")
		require.True(t, allowed)
		spray.RecordFailure(ip, "target"+string(rune('a'+i))+"@example.com")
	}
	_, allowed := spray.Check(ip, "another@example.com")
	assert.False(t, allowed, "one address must not keep spraying distinct accounts")

	shared := newThrottle(t, &LoginThrottleConfig{AttemptsPerMinute: 1, AttemptsBurst: 2})
	for i := 0; i < 20; i++ {
		_, allowed := shared.Check(ip, "ok"+string(rune('a'+i))+"@example.com")
		require.True(t, allowed, "successful sign-ins from a shared address must not be throttled")
		shared.RecordSuccess("ok" + string(rune('a'+i)) + "@example.com")
	}
}

// TestLoginThrottle_AccountKeyIsCaseAndSpaceInsensitive makes sure a trivial
// variation of the submitted login does not reset the per-account budget.
func TestLoginThrottle_AccountKeyIsCaseAndSpaceInsensitive(t *testing.T) {
	throttle := newThrottle(t, &LoginThrottleConfig{AccountFailureLimit: 2, AccountLockout: time.Minute})

	throttle.RecordFailure("203.0.113.1", "Victim@Example.com")
	throttle.RecordFailure("203.0.113.1", "  victim@example.COM  ")

	_, allowed := throttle.Check("203.0.113.1", "VICTIM@example.com")
	assert.False(t, allowed)
}

// TestLoginThrottle_BoundedEntries ensures a flood of distinct login values
// cannot grow the tracking maps without limit.
func TestLoginThrottle_BoundedEntries(t *testing.T) {
	throttle := newThrottle(t, &LoginThrottleConfig{
		AccountFailureLimit: 10000,
		MaxEntries:          50,
		EntryTTL:            time.Hour,
	})

	for i := 0; i < 500; i++ {
		account := "flood" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "@example.com"
		throttle.RecordFailure("203.0.113.1", account)
	}

	throttle.mu.Lock()
	accounts := len(throttle.accounts)
	ips := len(throttle.ips)
	throttle.mu.Unlock()

	assert.LessOrEqual(t, accounts, throttle.cfg.MaxEntries)
	assert.LessOrEqual(t, ips, throttle.cfg.MaxEntries)
}

// TestLoginThrottle_ClientIPHonoursTrustedProxies pins the address resolution:
// forwarding headers are believed only from configured proxies, so a client
// cannot escape an address budget by spoofing X-Forwarded-For.
func TestLoginThrottle_ClientIPHonoursTrustedProxies(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/oauth2/auth/local/login", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	req.Header.Set("X-Forwarded-For", "198.51.100.42")

	untrusted := newThrottle(t, nil)
	assert.Equal(t, "10.1.2.3", untrusted.clientIP(req), "untrusted forwarding headers must be ignored")

	trusted := newThrottle(t, &LoginThrottleConfig{
		TrustedProxies: mustParseTrustedProxies(t, "10.0.0.0/8"),
	})
	assert.Equal(t, "198.51.100.42", trusted.clientIP(req))
}

// TestIsLocalLoginSubmission pins which requests are treated as credential
// submissions.
func TestIsLocalLoginSubmission(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodPost, "/oauth2/auth/local/login", true},
		{http.MethodPost, "/oauth2/auth/local/login/", true},
		{http.MethodGet, "/oauth2/auth/local/login", false},
		{http.MethodGet, "/oauth2/auth/local", false},
		{http.MethodPost, "/oauth2/token", false},
		{http.MethodGet, "/oauth2/.well-known/openid-configuration", false},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		assert.Equal(t, tc.want, isLocalLoginSubmission(req), "%s %s", tc.method, tc.path)
	}
}

// TestHandler_ThrottlesLocalLoginAndKeepsDiscoveryOpen is the end-to-end check
// against the real embedded Dex: repeated wrong passwords eventually return 429
// with a Retry-After header, while OIDC discovery is unaffected and a locked
// account cannot be probed further.
func TestHandler_ThrottlesLocalLoginAndKeepsDiscoveryOpen(t *testing.T) {
	ctx := t.Context()

	tmpDir, err := os.MkdirTemp("", "dex-login-throttle-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	provider, err := NewProvider(ctx, &Config{
		Issuer:  "http://localhost:5566/oauth2",
		Port:    5566,
		DataDir: tmpDir,
	})
	require.NoError(t, err)
	defer func() { _ = provider.Stop(ctx) }()

	provider.loginLimiter.Store(newThrottle(t, &LoginThrottleConfig{
		AccountFailureLimit: 3,
		AccountLockout:      time.Minute,
		MaxAccountLockout:   time.Minute,
		AttemptsPerMinute:   1000,
		AttemptsBurst:       1000,
	}))

	handler := provider.Handler()

	post := func(password string) *httptest.ResponseRecorder {
		body := "login=locked%40example.com&password=" + password
		req := httptest.NewRequest(http.MethodPost, "/oauth2/auth/local/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.44:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// The first failures are answered by Dex itself, not the throttle. In this
	// isolated harness the request carries no auth request state, so Dex rejects
	// the submission with a 4xx rather than re-rendering the form with 401; live,
	// the same path returns 401. Either way the attempt reached Dex and is
	// counted as a failure, which is what the throttle must act on.
	for i := 0; i < 3; i++ {
		rec := post("wrongpass" + string(rune('0'+i)))
		require.NotEqual(t, http.StatusTooManyRequests, rec.Code,
			"attempt %d must reach Dex before the throttle engages", i+1)
		require.GreaterOrEqual(t, rec.Code, 400, "attempt %d must be rejected by Dex", i+1)
		require.Less(t, rec.Code, 500, "attempt %d must not be a server error", i+1)
	}

	rec := post("wrongpass9")
	require.Equal(t, http.StatusTooManyRequests, rec.Code, "the guessing budget must be exhausted")
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))

	// A correct password for the locked account is refused too: the lockout is
	// account-scoped, not credential-scoped.
	rec = post("correct-horse")
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)

	// Discovery and the rest of the OIDC plane stay open.
	req := httptest.NewRequest(http.MethodGet, "/oauth2/.well-known/openid-configuration", nil)
	discovery := httptest.NewRecorder()
	handler.ServeHTTP(discovery, req)
	assert.Equal(t, http.StatusOK, discovery.Code)
}

func mustParseTrustedProxies(t *testing.T, raw string) *trustedproxy.List {
	t.Helper()
	list, err := trustedproxy.Parse(raw)
	require.NoError(t, err)
	return list
}

// TestLoginSucceeded pins how a login submission is classified: only a
// redirect is a completed sign-in, so a rejected attempt always draws down the
// budget and a successful one never does.
func TestLoginSucceeded(t *testing.T) {
	assert.True(t, loginSucceeded(http.StatusFound))
	assert.True(t, loginSucceeded(http.StatusSeeOther))
	assert.False(t, loginSucceeded(http.StatusOK))
	assert.False(t, loginSucceeded(http.StatusUnauthorized))
	assert.False(t, loginSucceeded(http.StatusBadRequest))
	assert.False(t, loginSucceeded(http.StatusTooManyRequests))
}

// TestStatusRecorder_CapturesImplicitStatus makes sure a handler that writes a
// body without calling WriteHeader is recorded as 200, not as "nothing happened".
func TestStatusRecorder_CapturesImplicitStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	recorder := &statusRecorder{ResponseWriter: rec}
	_, err := recorder.Write([]byte("ok"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, recorder.status)

	empty := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	assert.Zero(t, empty.status, "a handler that wrote nothing must leave the status unset")
}
