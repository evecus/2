package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"github.com/yourusername/vane/config"
)

// ACME CA directory URLs
const (
	CALetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"
	CAZeroSSL     = "https://acme.zerossl.com/v2/DV90"
)

type Manager struct {
	cfg *config.Config
}

func NewManager(cfg *config.Config) *Manager {
	return &Manager{cfg: cfg}
}

func (m *Manager) StartAutoRenew() {
	go func() {
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()
		m.renewAll()
		for range ticker.C {
			m.renewAll()
		}
	}()
}

func (m *Manager) renewAll() {
	m.cfg.RLock()
	certs := make([]config.TLSCert, len(m.cfg.TLSCerts))
	copy(certs, m.cfg.TLSCerts)
	m.cfg.RUnlock()

	for _, c := range certs {
		if !c.AutoRenew || c.Source != "acme" {
			continue
		}
		days := c.DaysUntilExpiry()
		if days > 30 {
			continue
		}
		log.Printf("[tls] cert %s expires in %d days, renewing...", c.Domain, days)
		if err := m.IssueCert(c.ID); err != nil {
			log.Printf("[tls] renew %s error: %v", c.Domain, err)
		}
	}
}

// IssueCert triggers ACME DNS-01 cert issuance for a given cert config ID.
// Supports Let's Encrypt and ZeroSSL.
func (m *Manager) IssueCert(certID string) error {
	m.cfg.RLock()
	var cert *config.TLSCert
	for i := range m.cfg.TLSCerts {
		if m.cfg.TLSCerts[i].ID == certID {
			c := m.cfg.TLSCerts[i]
			cert = &c
			break
		}
	}
	m.cfg.RUnlock()
	if cert == nil {
		return fmt.Errorf("cert %s not found", certID)
	}
	if cert.Email == "" {
		return fmt.Errorf("email is required for ACME certificate issuance")
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	user := &acmeUser{email: cert.Email, key: privKey}
	legoConfig := lego.NewConfig(user)
	legoConfig.Certificate.KeyType = certcrypto.RSA2048

	// Select CA
	switch cert.CAProvider {
	case "zerossl":
		legoConfig.CADirURL = CAZeroSSL
	default: // "letsencrypt" or empty
		legoConfig.CADirURL = CALetsEncrypt
	}

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return fmt.Errorf("create lego client: %w", err)
	}

	// Setup DNS provider
	if err := setupDNSProvider(client, cert); err != nil {
		return err
	}

	// Register account
	var reg *registration.Resource
	if cert.CAProvider == "zerossl" && cert.ProviderConf.ZeroSSLAPIKey != "" {
		// ZeroSSL supports EAB (External Account Binding)
		reg, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  cert.ProviderConf.ZeroSSLKeyID,
			HmacEncoded:          cert.ProviderConf.ZeroSSLAPIKey,
		})
	} else {
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	}
	if err != nil {
		return fmt.Errorf("register ACME account: %w", err)
	}
	user.registration = reg

	// Request certificate
	request := certificate.ObtainRequest{
		Domains: []string{cert.Domain},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("obtain certificate: %w", err)
	}

	expiresAt := parseCertExpiry(certificates.Certificate)

	// Persist to config
	m.cfg.Lock()
	for i := range m.cfg.TLSCerts {
		if m.cfg.TLSCerts[i].ID == certID {
			m.cfg.TLSCerts[i].CertPEM = string(certificates.Certificate)
			m.cfg.TLSCerts[i].KeyPEM = string(certificates.PrivateKey)
			m.cfg.TLSCerts[i].IssuedAt = config.Now()
			m.cfg.TLSCerts[i].ExpiresAt = expiresAt
			m.cfg.TLSCerts[i].Status = "active"
			break
		}
	}
	m.cfg.Unlock()
	return m.cfg.Save()
}

// setupDNSProvider configures the ACME DNS-01 challenge provider.
func setupDNSProvider(client *lego.Client, cert *config.TLSCert) error {
	switch cert.Provider {
	case "cloudflare":
		cfCfg := cloudflare.NewDefaultConfig()
		cfCfg.AuthToken = cert.ProviderConf.APIToken
		// Increase propagation timeout for slow DNS providers
		cfCfg.PropagationTimeout = 10 * time.Minute
		cfCfg.PollingInterval = 15 * time.Second
		provider, err := cloudflare.NewDNSProviderConfig(cfCfg)
		if err != nil {
			return fmt.Errorf("cloudflare provider: %w", err)
		}
		return client.Challenge.SetDNS01Provider(provider,
			dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"}),
			dns01.DisableCompletePropagationRequirement(),
		)
	default:
		return fmt.Errorf("unsupported DNS provider: %s (supported: cloudflare)", cert.Provider)
	}
}

// ─── ACME user ────────────────────────────────────────────────────────────────

type acmeUser struct {
	email        string
	registration *registration.Resource
	key          *ecdsa.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// ─── Helpers ──────────────────────────────────────────────────────────────────

func parseCertExpiry(certPEM []byte) string {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return cert.NotAfter.UTC().Format(time.RFC3339)
}
