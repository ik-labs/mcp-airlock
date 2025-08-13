// Package security provides TLS configuration and certificate validation
package security

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// TLSConfig holds TLS configuration options
type TLSConfig struct {
	CertFile           string        `yaml:"cert_file"`
	KeyFile            string        `yaml:"key_file"`
	CAFile             string        `yaml:"ca_file,omitempty"`
	MinVersion         string        `yaml:"min_version"`
	CipherSuites       []string      `yaml:"cipher_suites,omitempty"`
	ClientAuth         string        `yaml:"client_auth,omitempty"`
	CertRefreshPeriod  time.Duration `yaml:"cert_refresh_period"`
	InsecureSkipVerify bool          `yaml:"insecure_skip_verify"`
}

// DefaultTLSConfig returns a secure TLS configuration with TLS 1.3 enforcement
func DefaultTLSConfig() *TLSConfig {
	return &TLSConfig{
		MinVersion:        "1.3",
		CertRefreshPeriod: 24 * time.Hour,
		ClientAuth:        "NoClientCert",
		CipherSuites: []string{
			"TLS_AES_256_GCM_SHA384",
			"TLS_CHACHA20_POLY1305_SHA256",
			"TLS_AES_128_GCM_SHA256",
		},
	}
}

// TLSManager manages TLS configuration and certificate lifecycle
type TLSManager struct {
	config   *TLSConfig
	logger   *zap.Logger
	tlsConf  *tls.Config
	certPair *tls.Certificate
}

// NewTLSManager creates a new TLS manager with the given configuration
func NewTLSManager(config *TLSConfig, logger *zap.Logger) (*TLSManager, error) {
	if config == nil {
		config = DefaultTLSConfig()
	}

	manager := &TLSManager{
		config: config,
		logger: logger,
	}

	// Build TLS configuration
	tlsConf, err := manager.buildTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS config: %w", err)
	}

	manager.tlsConf = tlsConf

	// Load initial certificate if provided
	if config.CertFile != "" && config.KeyFile != "" {
		if err := manager.loadCertificate(); err != nil {
			return nil, fmt.Errorf("failed to load certificate: %w", err)
		}
	}

	return manager, nil
}

// buildTLSConfig creates a secure TLS configuration
func (tm *TLSManager) buildTLSConfig() (*tls.Config, error) {
	// Parse minimum TLS version
	minVersion, err := tm.parseTLSVersion(tm.config.MinVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid min_version: %w", err)
	}

	// Parse cipher suites
	cipherSuites, err := tm.parseCipherSuites(tm.config.CipherSuites)
	if err != nil {
		return nil, fmt.Errorf("invalid cipher_suites: %w", err)
	}

	// Parse client auth mode
	clientAuth, err := tm.parseClientAuth(tm.config.ClientAuth)
	if err != nil {
		return nil, fmt.Errorf("invalid client_auth: %w", err)
	}

	tlsConf := &tls.Config{
		MinVersion:               minVersion,
		MaxVersion:               tls.VersionTLS13, // Enforce TLS 1.3 maximum
		CipherSuites:             cipherSuites,
		PreferServerCipherSuites: true,
		ClientAuth:               clientAuth,
		InsecureSkipVerify:       tm.config.InsecureSkipVerify,

		// Security hardening
		Renegotiation:          tls.RenegotiateNever,
		SessionTicketsDisabled: false, // Enable for performance

		// Certificate callback for dynamic loading
		GetCertificate: tm.getCertificate,
	}

	// Load CA certificates if specified
	if tm.config.CAFile != "" {
		caCert, err := ioutil.ReadFile(tm.config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConf.ClientCAs = caCertPool
		tlsConf.RootCAs = caCertPool
	}

	return tlsConf, nil
}

// parseTLSVersion converts string version to TLS constant
func (tm *TLSManager) parseTLSVersion(version string) (uint16, error) {
	switch version {
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version: %s", version)
	}
}

// parseCipherSuites converts string cipher suites to TLS constants
func (tm *TLSManager) parseCipherSuites(suites []string) ([]uint16, error) {
	if len(suites) == 0 {
		// Return secure defaults for TLS 1.3
		return []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		}, nil
	}

	cipherMap := map[string]uint16{
		"TLS_AES_256_GCM_SHA384":       tls.TLS_AES_256_GCM_SHA384,
		"TLS_CHACHA20_POLY1305_SHA256": tls.TLS_CHACHA20_POLY1305_SHA256,
		"TLS_AES_128_GCM_SHA256":       tls.TLS_AES_128_GCM_SHA256,
	}

	var result []uint16
	for _, suite := range suites {
		if cipher, ok := cipherMap[suite]; ok {
			result = append(result, cipher)
		} else {
			return nil, fmt.Errorf("unsupported cipher suite: %s", suite)
		}
	}

	return result, nil
}

// parseClientAuth converts string client auth mode to TLS constant
func (tm *TLSManager) parseClientAuth(auth string) (tls.ClientAuthType, error) {
	switch auth {
	case "", "NoClientCert":
		return tls.NoClientCert, nil
	case "RequestClientCert":
		return tls.RequestClientCert, nil
	case "RequireAnyClientCert":
		return tls.RequireAnyClientCert, nil
	case "VerifyClientCertIfGiven":
		return tls.VerifyClientCertIfGiven, nil
	case "RequireAndVerifyClientCert":
		return tls.RequireAndVerifyClientCert, nil
	default:
		return 0, fmt.Errorf("unsupported client auth mode: %s", auth)
	}
}

// loadCertificate loads the TLS certificate from files
func (tm *TLSManager) loadCertificate() error {
	cert, err := tls.LoadX509KeyPair(tm.config.CertFile, tm.config.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate pair: %w", err)
	}

	// Validate certificate
	if err := tm.validateCertificate(&cert); err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	tm.certPair = &cert
	tm.logger.Info("TLS certificate loaded successfully",
		zap.String("cert_file", tm.config.CertFile),
		zap.String("key_file", tm.config.KeyFile),
	)

	return nil
}

// validateCertificate performs security validation on the certificate
func (tm *TLSManager) validateCertificate(cert *tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("no certificate found")
	}

	// Parse the leaf certificate
	leafCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	// Check expiration
	now := time.Now()
	if now.Before(leafCert.NotBefore) {
		return fmt.Errorf("certificate not yet valid (NotBefore: %v)", leafCert.NotBefore)
	}
	if now.After(leafCert.NotAfter) {
		return fmt.Errorf("certificate expired (NotAfter: %v)", leafCert.NotAfter)
	}

	// Warn if certificate expires soon (30 days)
	if now.Add(30 * 24 * time.Hour).After(leafCert.NotAfter) {
		tm.logger.Warn("Certificate expires soon",
			zap.Time("expires_at", leafCert.NotAfter),
			zap.Duration("expires_in", leafCert.NotAfter.Sub(now)),
		)
	}

	// Check key usage
	if leafCert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("certificate missing required KeyUsageDigitalSignature")
	}

	// Check extended key usage for server authentication
	hasServerAuth := false
	for _, usage := range leafCert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		return fmt.Errorf("certificate missing ExtKeyUsageServerAuth")
	}

	tm.logger.Info("Certificate validation passed",
		zap.String("subject", leafCert.Subject.String()),
		zap.Time("not_before", leafCert.NotBefore),
		zap.Time("not_after", leafCert.NotAfter),
		zap.Strings("dns_names", leafCert.DNSNames),
	)

	return nil
}

// getCertificate returns the current certificate for TLS connections
func (tm *TLSManager) getCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if tm.certPair == nil {
		return nil, fmt.Errorf("no certificate available")
	}

	// Log TLS connection details for security monitoring
	tm.logger.Debug("TLS connection established",
		zap.String("server_name", clientHello.ServerName),
		zap.Uint16("supported_versions", clientHello.SupportedVersions[0]),
		zap.Strings("cipher_suites", tm.formatCipherSuites(clientHello.CipherSuites)),
	)

	return tm.certPair, nil
}

// formatCipherSuites converts cipher suite IDs to readable names
func (tm *TLSManager) formatCipherSuites(suites []uint16) []string {
	var names []string
	for _, suite := range suites {
		names = append(names, tls.CipherSuiteName(suite))
	}
	return names
}

// GetTLSConfig returns the configured TLS configuration
func (tm *TLSManager) GetTLSConfig() *tls.Config {
	return tm.tlsConf
}

// StartCertificateRefresh starts a goroutine to periodically refresh certificates
func (tm *TLSManager) StartCertificateRefresh(ctx context.Context) {
	if tm.config.CertRefreshPeriod <= 0 {
		tm.logger.Info("Certificate refresh disabled")
		return
	}

	go func() {
		ticker := time.NewTicker(tm.config.CertRefreshPeriod)
		defer ticker.Stop()

		tm.logger.Info("Started certificate refresh",
			zap.Duration("period", tm.config.CertRefreshPeriod),
		)

		for {
			select {
			case <-ticker.C:
				if err := tm.loadCertificate(); err != nil {
					tm.logger.Error("Certificate refresh failed", zap.Error(err))
				} else {
					tm.logger.Info("Certificate refreshed successfully")
				}
			case <-ctx.Done():
				tm.logger.Info("Certificate refresh stopped")
				return
			}
		}
	}()
}

// ConfigureHTTPServer applies TLS configuration to an HTTP server
func (tm *TLSManager) ConfigureHTTPServer(server *http.Server) {
	server.TLSConfig = tm.tlsConf

	// Additional security headers middleware
	originalHandler := server.Handler
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Content Security Policy for API endpoints
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		originalHandler.ServeHTTP(w, r)
	})
}
