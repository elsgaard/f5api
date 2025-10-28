package f5api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

const (
	defaultTimeout     = 10 * time.Second
	loginURL           = "/mgmt/shared/authn/login"
	refreshTokenURL    = "/mgmt/shared/authz/tokens/"
	poolStatsURL       = "/mgmt/tm/ltm/pool/stats"
	syncStatusURL      = "/mgmt/tm/cm/sync-status"
	tokenRefreshWindow = 5 * time.Minute // refresh before expiry
)

type Model struct {
	User       string
	Pass       string
	Host       string
	Port       string
	MaxRetries int
	RetryDelay time.Duration

	mu           sync.Mutex
	sessionToken string
	tokenExpires time.Time
	stopCh       chan struct{}
	running      bool
}

// -----------------------------
// Structs for Token Handling
// -----------------------------

type F5Token struct {
	Token struct {
		Token            string `json:"token"`
		ExpirationMicros int64  `json:"expirationMicros"`
	} `json:"token"`
}

// -----------------------------
// Structs for Pool Stats
// -----------------------------

type PoolStats struct {
	Entries map[string]Entry `json:"entries"`
}

type Entry struct {
	NestedStats NestedStats `json:"nestedStats"`
}

type NestedStats struct {
	Entries StatEntries `json:"entries"`
}

type StatEntries struct {
	ActiveMemberCnt         StatValue   `json:"activeMemberCnt"`
	AvailableMemberCnt      StatValue   `json:"availableMemberCnt"`
	MemberCnt               StatValue   `json:"memberCnt"`
	MinActiveMembers        StatValue   `json:"minActiveMembers"`
	ServersideCurConns      StatValue   `json:"serverside.curConns"`
	ServersideTotConns      StatValue   `json:"serverside.totConns"`
	StatusAvailabilityState StatMessage `json:"status.availabilityState"`
	StatusEnabledState      StatMessage `json:"status.enabledState"`
	StatusStatusReason      StatMessage `json:"status.statusReason"`
	TmName                  StatMessage `json:"tmName"`
}

type StatValue struct {
	Value int64 `json:"value"`
}

type StatMessage struct {
	Description string `json:"description"`
}

// -----------------------------
// Structs for Sync Status
// -----------------------------

type SyncStatusResponse struct {
	Entries map[string]SyncEntry `json:"entries"`
}

type SyncEntry struct {
	NestedStats struct {
		Entries struct {
			Status struct {
				Description string `json:"description"`
			} `json:"status"`
		} `json:"entries"`
	} `json:"nestedStats"`
}

// -----------------------------
// Token Lifecycle
// -----------------------------

// StartTokenRefresher launches a background goroutine that automatically refreshes the token.
func (m *Model) StartTokenRefresher() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.stopCh = make(chan struct{})
	m.running = true
	m.mu.Unlock()

	go func() {
		for {
			sleepDur := m.timeUntilRefresh()
			select {
			case <-time.After(sleepDur):
				if err := m.refreshToken(); err != nil {
					fmt.Println("[f5api] token refresh failed:", err)
					// Try full re-login on next cycle
					m.mu.Lock()
					m.sessionToken = ""
					m.mu.Unlock()
				}
			case <-m.stopCh:
				return
			}
		}
	}()
}

// StopTokenRefresher stops the background token refresher goroutine.
func (m *Model) StopTokenRefresher() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return
	}
	close(m.stopCh)
	m.running = false
}

func (m *Model) timeUntilRefresh() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tokenExpires.IsZero() {
		return 10 * time.Second
	}
	until := time.Until(m.tokenExpires.Add(-tokenRefreshWindow))
	if until < 10*time.Second {
		until = 10 * time.Second
	}
	return until
}

// refreshToken uses the existing token to extend its lifetime.
func (m *Model) refreshToken() error {
	token, err := m.getToken()
	if err != nil {
		return err
	}

	url := m.apiURL(refreshTokenURL + token)
	resp, err := m.doRequest("GET", url, "", nil, token)
	if err != nil {
		return fmt.Errorf("token refresh GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token refresh failed: HTTP %d", resp.StatusCode)
	}

	// Extend expiry again
	m.mu.Lock()
	m.tokenExpires = time.Now().Add(9 * time.Hour)
	m.mu.Unlock()
	return nil
}

// getToken ensures a valid token exists and returns it.
func (m *Model) getToken() (string, error) {
	m.mu.Lock()
	if m.sessionToken != "" && time.Now().Before(m.tokenExpires.Add(-tokenRefreshWindow)) {
		token := m.sessionToken
		m.mu.Unlock()
		return token, nil
	}
	m.mu.Unlock()

	// Re-login
	payload := map[string]string{
		"username":          m.User,
		"password":          m.Pass,
		"loginProviderName": "tmos",
	}
	data, _ := json.Marshal(payload)

	resp, err := m.doRequest("POST", m.apiURL(loginURL), "application/json", bytes.NewReader(data), "")
	if err != nil {
		return "", fmt.Errorf("authentication request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authentication failed: HTTP %d", resp.StatusCode)
	}

	var tokenResp F5Token
	if err := decodeJSON(resp.Body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse auth response: %w", err)
	}

	expMicros := tokenResp.Token.ExpirationMicros
	exp := time.Now().Add(9 * time.Hour) // fallback
	if expMicros > 0 {
		exp = time.UnixMicro(expMicros)
	}

	m.mu.Lock()
	m.sessionToken = tokenResp.Token.Token
	m.tokenExpires = exp
	m.mu.Unlock()

	return tokenResp.Token.Token, nil
}

// -----------------------------
// API Methods
// -----------------------------

func (m *Model) GetPoolStats() (PoolStats, error) {
	token, err := m.getToken()
	if err != nil {
		return PoolStats{}, err
	}

	resp, err := m.doRequest("GET", m.apiURL(poolStatsURL), "", nil, token)
	if err != nil {
		return PoolStats{}, fmt.Errorf("pool stats request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return PoolStats{}, fmt.Errorf("failed to get pool stats: HTTP %d", resp.StatusCode)
	}

	var stats PoolStats
	if err := decodeJSON(resp.Body, &stats); err != nil {
		return PoolStats{}, fmt.Errorf("failed to decode pool stats: %w", err)
	}

	return stats, nil
}

func (m *Model) GetSyncStatus() (int, error) {
	token, err := m.getToken()
	if err != nil {
		return 0, err
	}

	resp, err := m.doRequest("GET", m.apiURL(syncStatusURL), "", nil, token)
	if err != nil {
		return 0, fmt.Errorf("sync status request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("failed to get sync status: HTTP %d", resp.StatusCode)
	}

	var result SyncStatusResponse
	if err := decodeJSON(resp.Body, &result); err != nil {
		return 0, fmt.Errorf("failed to decode sync status: %w", err)
	}

	for _, entry := range result.Entries {
		status := entry.NestedStats.Entries.Status.Description
		if status == "In Sync" {
			return 1, nil
		}
		break
	}
	return 0, nil
}

// -----------------------------
// HTTP Request Handling
// -----------------------------

func (m *Model) doRequest(method, url, contentType string, body io.Reader, token string) (*http.Response, error) {
	if m.MaxRetries <= 0 {
		m.MaxRetries = 3
	}
	if m.RetryDelay <= 0 {
		m.RetryDelay = 500 * time.Millisecond
	}

	client := &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ⚠️ disable in production
		},
	}

	var lastErr error
	backoff := m.RetryDelay

	var bodyBytes []byte
	if body != nil {
		bodyBytes, _ = io.ReadAll(body)
	}

	for attempt := 0; attempt <= m.MaxRetries; attempt++ {
		var reqBody io.Reader
		if bodyBytes != nil {
			reqBody = bytes.NewReader(bodyBytes)
		}

		req, err := http.NewRequest(method, url, reqBody)
		if err != nil {
			return nil, err
		}
		req.Close = true

		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if token != "" {
			req.Header.Set("X-F5-Auth-Token", token)
		}

		resp, err := client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		lastErr = err

		if attempt < m.MaxRetries {
			jitter := time.Duration(float64(backoff) * (0.5 + rand.Float64()*0.5))
			time.Sleep(jitter)
			backoff *= 2
		}
	}
	return nil, fmt.Errorf("request failed after %d attempts: %w", m.MaxRetries+1, lastErr)
}

// -----------------------------
// Helpers
// -----------------------------

func (m *Model) apiURL(path string) string {
	return fmt.Sprintf("https://%s:%s%s", m.Host, m.Port, path)
}

func decodeJSON(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}
