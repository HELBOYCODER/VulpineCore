// Package prefs reads Vulpine VPN's stored Firefox-account session.
//
// On macOS the desktop app keeps its tokens in an AES-256-GCM encrypted
// properties file: each entry is stored as sha256("foxy:"+name) = base64(iv):
// base64(ciphertext), keyed by a 32-byte file under keys/. The core reuses that
// session for local verification so the Go tunnel can be exercised against the
// real edge without a second sign-in; on iOS the same values come from the
// app's own keychain instead.
package prefs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const keyPrefix = "foxy:"

// Auth is the stored Firefox-account session.
type Auth struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    int64
}

// Dir returns Vulpine's data directory, honouring VULPINE_DATA_DIR for tests.
func Dir() (string, error) {
	if custom := os.Getenv("VULPINE_DATA_DIR"); custom != "" {
		return custom, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "FoxyVPN"), nil
}

// LoadAuth decrypts the stored session from the desktop app's preferences.
func LoadAuth() (*Auth, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(filepath.Join(dir, "keys", "foxyvpn_tokens.key"))
	if err != nil {
		return nil, fmt.Errorf("token key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("token key has %d bytes, want 32", len(key))
	}
	entries, err := readProperties(filepath.Join(dir, "prefs", "foxyvpn_tokens.properties"))
	if err != nil {
		return nil, err
	}
	access, err := typedSecret(key, entries, "access_token", "s")
	if err != nil {
		return nil, err
	}
	refresh, _ := typedSecret(key, entries, "refresh_token", "s")
	expiresRaw, _ := typedSecret(key, entries, "expires_at", "l")
	expires, _ := strconv.ParseInt(expiresRaw, 10, 64)
	if access == "" {
		return nil, errors.New("stored access token is empty; sign in through Vulpine first")
	}
	return &Auth{AccessToken: access, RefreshToken: refresh, ExpiresAt: expires}, nil
}

// typedSecret decrypts one entry and strips the one-character type tag the
// desktop app prefixes every value with (s string, l long, i int, b bool).
func typedSecret(key []byte, entries map[string]string, name, kind string) (string, error) {
	raw, err := secret(key, entries, name)
	if err != nil {
		return "", err
	}
	if len(raw) < 1 || string(raw[0]) != kind {
		return "", fmt.Errorf("preference %q has type %q, want %q", name, firstChar(raw), kind)
	}
	return raw[1:], nil
}

func firstChar(s string) string {
	if s == "" {
		return ""
	}
	return string(s[0])
}

func secret(key []byte, entries map[string]string, name string) (string, error) {
	hashed := hex.EncodeToString(sha256Sum([]byte(keyPrefix + name)))
	encoded, ok := entries[hashed]
	if !ok {
		return "", fmt.Errorf("preference %q not stored", name)
	}
	parts := strings.SplitN(encoded, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("preference %q has an unexpected layout", name)
	}
	iv, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	clear, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(clear), nil
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func readProperties(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("prefs: %w", err)
	}
	out := make(map[string]string)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		out[unescape(strings.TrimSpace(name))] = unescape(value)
	}
	return out, nil
}

// unescape undoes the escapes java.util.Properties.store writes into a file:
// it backslash-escapes ':' and '=' even inside values.
func unescape(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'u':
			if i+4 < len(s) {
				if code, err := strconv.ParseUint(s[i+1:i+5], 16, 16); err == nil {
					b.WriteRune(rune(code))
					i += 4
					continue
				}
			}
			b.WriteByte(s[i])
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
