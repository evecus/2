package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ─── Encryption ──────────────────────────────────────────────────────────────

const encryptionKeyEnv = "VANE_SECRET"

func deriveKey(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
}

// Encrypt encrypts plaintext with AES-256-GCM; returns hex(nonce+ciphertext).
func Encrypt(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(ct), nil
}

// Decrypt reverses Encrypt.
func Decrypt(key []byte, hexCT string) ([]byte, error) {
	ct, err := hex.DecodeString(hexCT)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ct) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ct[:gcm.NonceSize()], ct[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// ─── Data directory layout ───────────────────────────────────────────────────
//
//   <exe_dir>/data/
//     secret.key      — hex AES-256 key (mode 0600)
//     config.enc      — AES-GCM encrypted JSON config
//     backups/        — encrypted backup snapshots  *.enc

type DataDir struct {
	Root    string
	Backups string
	Key     []byte // 32-byte AES key
}

func NewDataDir() (*DataDir, error) {
	exe, err := os.Executable()
	if err != nil {
		exe = "."
	}
	root := filepath.Join(filepath.Dir(exe), "data")
	backups := filepath.Join(root, "backups")
	for _, d := range []string{root, backups} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return nil, fmt.Errorf("create data dir %s: %w", d, err)
		}
	}
	dd := &DataDir{Root: root, Backups: backups}
	if err := dd.loadOrCreateKey(); err != nil {
		return nil, err
	}
	return dd, nil
}

func (dd *DataDir) loadOrCreateKey() error {
	if secret := os.Getenv(encryptionKeyEnv); secret != "" {
		dd.Key = deriveKey(secret)
		return nil
	}
	keyFile := filepath.Join(dd.Root, "secret.key")
	data, err := os.ReadFile(keyFile)
	if os.IsNotExist(err) {
		raw := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, raw); err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		encoded := hex.EncodeToString(raw)
		if err := os.WriteFile(keyFile, []byte(encoded), 0600); err != nil {
			return fmt.Errorf("write secret.key: %w", err)
		}
		dd.Key = raw
		return nil
	}
	if err != nil {
		return fmt.Errorf("read secret.key: %w", err)
	}
	raw, err := hex.DecodeString(string(data))
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("invalid secret.key content")
	}
	dd.Key = raw
	return nil
}

func (dd *DataDir) ConfigPath() string {
	return filepath.Join(dd.Root, "config.enc")
}

// ─── Top-level config ────────────────────────────────────────────────────────

type Config struct {
	mu           sync.RWMutex      `json:"-"`
	dataDir      *DataDir          `json:"-"`
	Admin        AdminConfig       `json:"admin"`
	PortForwards []PortForwardRule `json:"port_forwards"`
	DDNS         []DDNSRule        `json:"ddns"`
	WebServices  []WebService      `json:"web_services"`
	TLSCerts     []TLSCert         `json:"tls_certs"`
}

// ─── Admin ───────────────────────────────────────────────────────────────────

type AdminConfig struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"` // bcrypt
	Port         int    `json:"port"`
	SafeEntry    string `json:"safe_entry"`
}

func (a *AdminConfig) CheckPassword(plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(plain)) == nil
}

func (a *AdminConfig) SetPassword(plain string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	a.PasswordHash = string(hash)
	return nil
}

// ─── Port Forward ────────────────────────────────────────────────────────────

type PortForwardRule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Protocol   string `json:"protocol"` // tcp | udp | both
	ListenPort int    `json:"listen_port"`
	TargetIP   string `json:"target_ip"`
	TargetPort int    `json:"target_port"`
	Enabled    bool   `json:"enabled"`
	CreatedAt  string `json:"created_at"`
}

// ─── DDNS ────────────────────────────────────────────────────────────────────

type DDNSRule struct {
	ID             string       `json:"id"`
	Name           string       `json:"name"`
	Provider       string       `json:"provider"`
	// Domains holds one or more FQDNs to update, e.g. ["home.example.com","*.example.com"]
	Domains        []string     `json:"domains"`
	// Legacy single-domain fields kept for migration
	Domain         string       `json:"domain,omitempty"`
	SubDomain      string       `json:"sub_domain,omitempty"`
	IPVersion      string       `json:"ip_version"`
	// IPDetectMode: "api" (external, proxy-free) or "iface" (read local network interface)
	IPDetectMode   string       `json:"ip_detect_mode"`
	IPInterface    string       `json:"ip_interface"` // e.g. "eth0", only used when mode=iface
	Interval       int          `json:"interval"`
	Enabled        bool         `json:"enabled"`
	ProviderConf   ProviderConf `json:"provider_conf"`
	LastIP         string       `json:"last_ip"`
	LastUpdated    string       `json:"last_updated"`
	IPHistory      []IPRecord   `json:"ip_history"`
	CreatedAt      string       `json:"created_at"`
}

type ProviderConf struct {
	APIToken        string `json:"api_token,omitempty"`
	ZoneID          string `json:"zone_id,omitempty"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	AccessKeySecret string `json:"access_key_secret,omitempty"`
	SecretID        string `json:"secret_id,omitempty"`
	SecretKey       string `json:"secret_key,omitempty"`
	// ZeroSSL EAB credentials (External Account Binding)
	ZeroSSLAPIKey string `json:"zerossl_api_key,omitempty"`
	ZeroSSLKeyID  string `json:"zerossl_key_id,omitempty"`
}

type IPRecord struct {
	IP        string `json:"ip"`
	Timestamp string `json:"timestamp"`
}

// ─── Web Service ─────────────────────────────────────────────────────────────

type WebService struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	ListenPort  int        `json:"listen_port"`
	TLSCertID   string     `json:"tls_cert_id"`
	EnableHTTPS bool       `json:"enable_https"`
	Enabled     bool       `json:"enabled"`
	Routes      []WebRoute `json:"routes"`
	CreatedAt   string     `json:"created_at"`
}

type WebRoute struct {
	ID         string `json:"id"`
	Domain     string `json:"domain"`
	BackendURL string `json:"backend_url"`
	Enabled    bool   `json:"enabled"`
	CreatedAt  string `json:"created_at"`
}

type WebAccessLog struct {
	ID         string `json:"id"`
	ServiceID  string `json:"service_id"`
	RouteID    string `json:"route_id"`
	Domain     string `json:"domain"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	DurationMs int64  `json:"duration_ms"`
	ClientIP   string `json:"client_ip"`
	UserAgent  string `json:"user_agent"`
	Referer    string `json:"referer"`
	Time       string `json:"time"`
}

// ─── TLS Cert ────────────────────────────────────────────────────────────────

type TLSCert struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`     // human-readable task name
	// Domains holds all SANs for this cert, e.g. ["example.com","*.example.com"]
	Domains      []string     `json:"domains"`
	// Domain kept for single-domain legacy & display
	Domain       string       `json:"domain,omitempty"`
	Source       string       `json:"source"`       // acme | manual
	CAProvider   string       `json:"ca_provider"`  // letsencrypt | zerossl
	Provider     string       `json:"provider"`     // DNS provider: cloudflare | ...
	ProviderConf ProviderConf `json:"provider_conf"`
	CertPEM      string       `json:"cert_pem"`
	KeyPEM       string       `json:"key_pem"`
	IssuedAt     string       `json:"issued_at"`
	ExpiresAt    string       `json:"expires_at"`
	AutoRenew    bool         `json:"auto_renew"`
	Email        string       `json:"email"`
	Status       string       `json:"status"`
	CreatedAt    string       `json:"created_at"`
}

func (c *TLSCert) DaysUntilExpiry() int {
	if c.ExpiresAt == "" {
		return -1
	}
	t, err := time.Parse(time.RFC3339, c.ExpiresAt)
	if err != nil {
		return -1
	}
	return int(time.Until(t).Hours() / 24)
}

// ─── Load / Save ─────────────────────────────────────────────────────────────

func Load(dd *DataDir) (*Config, error) {
	cfg := &Config{dataDir: dd}
	data, err := os.ReadFile(dd.ConfigPath())
	if os.IsNotExist(err) {
		return cfg.initDefaults()
	}
	if err != nil {
		return nil, err
	}
	plain, err := Decrypt(dd.Key, string(data))
	if err != nil {
		return nil, fmt.Errorf("decrypt config: %w", err)
	}
	if err := json.Unmarshal(plain, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.dataDir = dd
	return cfg, nil
}

// Save encrypts config and writes atomically. Caller must NOT hold any lock.
func (c *Config) Save() error {
	c.mu.RLock()
	plain, err := json.MarshalIndent(c, "", "  ")
	c.mu.RUnlock()
	if err != nil {
		return err
	}
	enc, err := Encrypt(c.dataDir.Key, plain)
	if err != nil {
		return fmt.Errorf("encrypt config: %w", err)
	}
	tmp := c.dataDir.ConfigPath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(enc), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, c.dataDir.ConfigPath())
}

// Export returns encrypted bytes for backup download (same key).
func (c *Config) Export() ([]byte, error) {
	c.mu.RLock()
	plain, err := json.MarshalIndent(c, "", "  ")
	c.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	enc, err := Encrypt(c.dataDir.Key, plain)
	if err != nil {
		return nil, err
	}
	return []byte(enc), nil
}

// Import restores config from an encrypted backup blob.
// Falls back to plain JSON for migration compatibility.
func (c *Config) Import(data []byte) error {
	plain, err := Decrypt(c.dataDir.Key, string(data))
	if err != nil {
		// Migration: try plain JSON
		plain = data
	}
	var tmp Config
	if err := json.Unmarshal(plain, &tmp); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	c.mu.Lock()
	c.Admin = tmp.Admin
	c.PortForwards = tmp.PortForwards
	c.DDNS = tmp.DDNS
	c.WebServices = tmp.WebServices
	c.TLSCerts = tmp.TLSCerts
	c.mu.Unlock()
	return c.Save()
}

// SaveBackup writes an encrypted snapshot to data/backups/<timestamp>.enc
func (c *Config) SaveBackup() (string, error) {
	enc, err := c.Export()
	if err != nil {
		return "", err
	}
	name := fmt.Sprintf("backup-%s.enc", time.Now().UTC().Format("20060102-150405"))
	path := filepath.Join(c.dataDir.Backups, name)
	if err := os.WriteFile(path, enc, 0600); err != nil {
		return "", err
	}
	return name, nil
}

func (c *Config) initDefaults() (*Config, error) {
	c.Admin = AdminConfig{Username: "admin", Port: 4455}
	if err := c.Admin.SetPassword("admin"); err != nil {
		return nil, err
	}
	c.PortForwards = []PortForwardRule{}
	c.DDNS = []DDNSRule{}
	c.WebServices = []WebService{}
	c.TLSCerts = []TLSCert{}
	_ = c.Save()
	return c, nil
}

// ─── Thread-safe helpers ─────────────────────────────────────────────────────

func (c *Config) Lock()    { c.mu.Lock() }
func (c *Config) Unlock()  { c.mu.Unlock() }
func (c *Config) RLock()   { c.mu.RLock() }
func (c *Config) RUnlock() { c.mu.RUnlock() }

// ─── Utilities ───────────────────────────────────────────────────────────────

// NewID returns a cryptographically random 32-hex-char ID.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// IsPortAvailable returns true if TCP port is not currently bound on the host.
func IsPortAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}
