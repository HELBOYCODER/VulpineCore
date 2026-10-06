// Package controlplane talks to Mozilla's Guardian API and Remote Settings,
// the two endpoints that turn a Firefox account into a live tunnel target.
package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// GuardianDefault is the API base for proxy passes and account status.
	GuardianDefault = "https://vpn.mozilla.org"
	// RemoteSettingsURL publishes the VPN server list Mozilla maintains.
	RemoteSettingsURL = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"
	// UserAgent mirrors what the official client sends; the edge checks it.
	UserAgent = "MozillaVPN/2.35.0 (sys:linux; iap:true)"
	// RecommendedCountry picks whatever Mozilla's anycast front prefers.
	RecommendedCountry = "REC"
)

// ErrTokenInvalid means Guardian rejected the account's access token.
type ErrTokenInvalid struct{ StatusCode int }

func (e ErrTokenInvalid) Error() string {
	return fmt.Sprintf("guardian rejected the access token (HTTP %d)", e.StatusCode)
}

// ErrQuotaExceeded means the account used up its monthly allowance.
type ErrQuotaExceeded struct{}

func (ErrQuotaExceeded) Error() string { return "account proxy quota exceeded" }

// ProxyPass is the short-lived bearer token the edge accepts for CONNECT.
type ProxyPass struct {
	Token          string
	ExpiresAt      int64
	QuotaMax       int64
	QuotaRemaining int64
	QuotaReset     int64
}

// RemainingSeconds reports how much life the pass has left.
func (p ProxyPass) RemainingSeconds() int64 {
	if p.ExpiresAt == 0 {
		return -1
	}
	return p.ExpiresAt - time.Now().Unix()
}

// Candidate is one edge the tunnel can dial.
type Candidate struct {
	Host        string
	Port        int
	CountryCode string
	CountryName string
	CityCode    string
}

func (c Candidate) Authority() string {
	if strings.Contains(c.Host, ":") {
		return "[" + c.Host + "]:" + strconv.Itoa(c.Port)
	}
	return c.Host + ":" + strconv.Itoa(c.Port)
}

// FetchProxyPass exchanges an OAuth access token for a proxy pass.
func FetchProxyPass(ctx context.Context, client *http.Client, endpoint, accessToken string) (*ProxyPass, error) {
	url := strings.TrimRight(endpoint, "/") + "/api/v1/fpn/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	decorate(req, accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return nil, ErrTokenInvalid{StatusCode: resp.StatusCode}
	case resp.StatusCode == 429:
		return nil, ErrQuotaExceeded{}
	case resp.StatusCode == 406:
		return nil, fmt.Errorf("guardian demanded a fastly challenge (HTTP 406) before issuing a pass")
	case resp.StatusCode != 200:
		return nil, fmt.Errorf("proxy pass fetch: HTTP %d: %s", resp.StatusCode, truncate(string(body), 300))
	}
	var payload struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("proxy pass response: %w", err)
	}
	if payload.Token == "" {
		return nil, fmt.Errorf("proxy pass response carried no token")
	}
	pass := &ProxyPass{Token: payload.Token, ExpiresAt: payload.ExpiresAt}
	if pass.ExpiresAt == 0 {
		pass.ExpiresAt = jwtExpiry(payload.Token)
	}
	pass.QuotaMax = headerInt(resp, "X-Quota-Limit")
	pass.QuotaRemaining = headerInt(resp, "X-Quota-Remaining")
	pass.QuotaReset = headerInt(resp, "X-Quota-Reset")
	return pass, nil
}

// Candidates lists the non-quarantined edges for a country code.
func Candidates(ctx context.Context, client *http.Client, countryCode string) ([]Candidate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, RemoteSettingsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("remote settings: HTTP %d", resp.StatusCode)
	}
	var records struct {
		Data []struct {
			Country *Country `json:"country"`
			CountryFields
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&records); err != nil {
		return nil, err
	}
	out := []Candidate{}
	for _, record := range records.Data {
		country := record.Country
		if country == nil {
			country = &record.CountryFields
		}
		if country.Code == "" || len(country.Cities) == 0 {
			continue
		}
		if !strings.EqualFold(country.Code, countryCode) {
			continue
		}
		for _, city := range country.Cities {
			for _, server := range city.Servers {
				if server.Quarantined {
					continue
				}
				host, port, ok := server.connectTarget()
				if !ok {
					continue
				}
				out = append(out, Candidate{
					Host: host, Port: port,
					CountryCode: country.Code, CountryName: country.Name,
					CityCode: city.Code,
				})
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable edge found for country %q", countryCode)
	}
	return out, nil
}

// CountryFields lets a record carry the country inline instead of nested.
type CountryFields = Country

type Country struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Cities []struct {
		Name    string `json:"name"`
		Code    string `json:"code"`
		Servers []Server
	} `json:"cities"`
}

type Server struct {
	Hostname    string     `json:"hostname"`
	Port        int        `json:"port"`
	Quarantined bool       `json:"quarantined"`
	Protocols   []Protocol `json:"protocols"`
}

type Protocol struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

// connectTarget picks the HTTP/2 CONNECT endpoint for a server node, matching
// the desktop client: the "connect" protocol wins, else the bare hostname.
func (s Server) connectTarget() (string, int, bool) {
	for _, proto := range s.Protocols {
		if proto.Name != "connect" {
			continue
		}
		host := proto.Host
		if host == "" {
			host = s.Hostname
		}
		port := proto.Port
		if port == 0 {
			port = s.Port
		}
		if host == "" || port == 0 {
			return "", 0, false
		}
		return host, port, true
	}
	if len(s.Protocols) == 0 && s.Hostname != "" && s.Port != 0 {
		return s.Hostname, s.Port, true
	}
	return "", 0, false
}

func decorate(req *http.Request, accessToken string) {
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
}

func headerInt(resp *http.Response, name string) int64 {
	value, _ := strconv.ParseInt(resp.Header.Get(name), 10, 64)
	return value
}

// jwtExpiry reads the exp claim out of the pass without verifying its
// signature — Guardian also sends expires_at, this is the fallback.
func jwtExpiry(token string) int64 {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return 0
	}
	payload := parts[1]
	for len(payload)%4 != 0 {
		payload += "="
	}
	raw, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return 0
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return 0
	}
	return claims.Exp
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
