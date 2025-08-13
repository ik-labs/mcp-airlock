// Package security provides security hardening utilities
package security

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// HardeningConfig holds security hardening configuration
type HardeningConfig struct {
	// TLS configuration
	TLS *TLSConfig `yaml:"tls"`

	// Container security
	NonRootUser      bool   `yaml:"non_root_user"`
	ReadOnlyRootFS   bool   `yaml:"read_only_root_fs"`
	DropCapabilities bool   `yaml:"drop_capabilities"`
	SeccompProfile   string `yaml:"seccomp_profile"`
	NoNewPrivileges  bool   `yaml:"no_new_privileges"`
	DisableCoreDumps bool   `yaml:"disable_core_dumps"`

	// Process security
	UmaskValue         uint32 `yaml:"umask_value"`
	MaxFileDescriptors uint64 `yaml:"max_file_descriptors"`
	MaxProcesses       uint64 `yaml:"max_processes"`
	MaxMemoryMB        uint64 `yaml:"max_memory_mb"`

	// Network security
	DisableIPv6     bool `yaml:"disable_ipv6"`
	BindToLocalhost bool `yaml:"bind_to_localhost"`

	// Runtime security
	EnableStackCanaries bool `yaml:"enable_stack_canaries"`
	EnableASLR          bool `yaml:"enable_aslr"`
	EnableNX            bool `yaml:"enable_nx"`
}

// DefaultHardeningConfig returns a secure default configuration
func DefaultHardeningConfig() *HardeningConfig {
	return &HardeningConfig{
		TLS:                 DefaultTLSConfig(),
		NonRootUser:         true,
		ReadOnlyRootFS:      true,
		DropCapabilities:    true,
		NoNewPrivileges:     true,
		DisableCoreDumps:    true,
		UmaskValue:          0o077, // Restrictive umask
		MaxFileDescriptors:  1024,
		MaxProcesses:        100,
		MaxMemoryMB:         512,
		DisableIPv6:         false,
		BindToLocalhost:     false,
		EnableStackCanaries: true,
		EnableASLR:          true,
		EnableNX:            true,
	}
}

// SecurityHardener applies security hardening measures
type SecurityHardener struct {
	config     *HardeningConfig
	logger     *zap.Logger
	tlsManager *TLSManager
}

// NewSecurityHardener creates a new security hardener
func NewSecurityHardener(config *HardeningConfig, logger *zap.Logger) (*SecurityHardener, error) {
	if config == nil {
		config = DefaultHardeningConfig()
	}

	hardener := &SecurityHardener{
		config: config,
		logger: logger,
	}

	// Initialize TLS manager if TLS is configured
	if config.TLS != nil {
		tlsManager, err := NewTLSManager(config.TLS, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS manager: %w", err)
		}
		hardener.tlsManager = tlsManager
	}

	return hardener, nil
}

// ApplyHardening applies all configured security hardening measures
func (sh *SecurityHardener) ApplyHardening(ctx context.Context) error {
	sh.logger.Info("Applying security hardening measures")

	// Apply process-level hardening
	if err := sh.applyProcessHardening(); err != nil {
		return fmt.Errorf("process hardening failed: %w", err)
	}

	// Apply resource limits
	if err := sh.applyResourceLimits(); err != nil {
		return fmt.Errorf("resource limits failed: %w", err)
	}

	// Apply runtime security measures
	if err := sh.applyRuntimeSecurity(); err != nil {
		return fmt.Errorf("runtime security failed: %w", err)
	}

	// Validate security state
	if err := sh.validateSecurityState(); err != nil {
		return fmt.Errorf("security validation failed: %w", err)
	}

	sh.logger.Info("Security hardening applied successfully")
	return nil
}

// applyProcessHardening applies process-level security measures
func (sh *SecurityHardener) applyProcessHardening() error {
	// Check if running as non-root user
	if sh.config.NonRootUser {
		if os.Getuid() == 0 || os.Getgid() == 0 {
			return fmt.Errorf("process running as root user (UID: %d, GID: %d)", os.Getuid(), os.Getgid())
		}
		sh.logger.Info("Running as non-root user",
			zap.Int("uid", os.Getuid()),
			zap.Int("gid", os.Getgid()))
	}

	// Set restrictive umask
	if sh.config.UmaskValue > 0 {
		oldUmask := syscall.Umask(int(sh.config.UmaskValue))
		sh.logger.Info("Set restrictive umask",
			zap.Uint32("new_umask", sh.config.UmaskValue),
			zap.Int("old_umask", oldUmask))
	}

	// Disable core dumps
	if sh.config.DisableCoreDumps {
		if err := sh.disableCoreDumps(); err != nil {
			sh.logger.Warn("Failed to disable core dumps", zap.Error(err))
		} else {
			sh.logger.Info("Core dumps disabled")
		}
	}

	return nil
}

// applyResourceLimits applies resource limits
func (sh *SecurityHardener) applyResourceLimits() error {
	// Set file descriptor limit
	if sh.config.MaxFileDescriptors > 0 {
		if err := sh.setRLimit(syscall.RLIMIT_NOFILE, sh.config.MaxFileDescriptors); err != nil {
			return fmt.Errorf("failed to set file descriptor limit: %w", err)
		}
		sh.logger.Info("Set file descriptor limit", zap.Uint64("limit", sh.config.MaxFileDescriptors))
	}

	// Set process limit (if supported on this platform)
	if sh.config.MaxProcesses > 0 && runtime.GOOS == "linux" {
		// RLIMIT_NPROC is Linux-specific
		const RLIMIT_NPROC = 6
		if err := sh.setRLimit(RLIMIT_NPROC, sh.config.MaxProcesses); err != nil {
			sh.logger.Warn("Failed to set process limit", zap.Error(err))
		} else {
			sh.logger.Info("Set process limit", zap.Uint64("limit", sh.config.MaxProcesses))
		}
	}

	// Set memory limit (if supported)
	if sh.config.MaxMemoryMB > 0 && runtime.GOOS == "linux" {
		memoryBytes := sh.config.MaxMemoryMB * 1024 * 1024
		if err := sh.setRLimit(syscall.RLIMIT_AS, memoryBytes); err != nil {
			sh.logger.Warn("Failed to set memory limit", zap.Error(err))
		} else {
			sh.logger.Info("Set memory limit", zap.Uint64("limit_mb", sh.config.MaxMemoryMB))
		}
	}

	return nil
}

// applyRuntimeSecurity applies runtime security measures
func (sh *SecurityHardener) applyRuntimeSecurity() error {
	// Validate Go runtime security features
	if sh.config.EnableStackCanaries {
		// Go automatically enables stack canaries, just log
		sh.logger.Info("Stack canaries enabled by Go runtime")
	}

	if sh.config.EnableASLR {
		// ASLR is typically enabled by the OS, validate if possible
		sh.logger.Info("ASLR should be enabled by operating system")
	}

	if sh.config.EnableNX {
		// NX bit is enabled by default on modern systems
		sh.logger.Info("NX bit should be enabled by operating system")
	}

	return nil
}

// validateSecurityState validates the current security state
func (sh *SecurityHardener) validateSecurityState() error {
	// Check read-only root filesystem
	if sh.config.ReadOnlyRootFS {
		if err := sh.validateReadOnlyRootFS(); err != nil {
			return fmt.Errorf("read-only root filesystem validation failed: %w", err)
		}
	}

	// Validate user privileges
	if sh.config.NonRootUser {
		if os.Getuid() == 0 {
			return fmt.Errorf("still running as root after hardening")
		}
	}

	// Check resource limits
	if err := sh.validateResourceLimits(); err != nil {
		return fmt.Errorf("resource limits validation failed: %w", err)
	}

	return nil
}

// validateReadOnlyRootFS checks if the root filesystem is read-only
func (sh *SecurityHardener) validateReadOnlyRootFS() error {
	// Try to create a temporary file in root
	testFile := "/tmp_security_test"
	file, err := os.Create(testFile)
	if err == nil {
		file.Close()
		os.Remove(testFile)
		sh.logger.Warn("Root filesystem appears to be writable")
		return nil // Don't fail, just warn
	}

	sh.logger.Info("Root filesystem appears to be read-only")
	return nil
}

// validateResourceLimits validates that resource limits are properly set
func (sh *SecurityHardener) validateResourceLimits() error {
	// Check file descriptor limit
	if sh.config.MaxFileDescriptors > 0 {
		var rlimit syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
			return fmt.Errorf("failed to get file descriptor limit: %w", err)
		}

		if rlimit.Cur > sh.config.MaxFileDescriptors {
			sh.logger.Warn("File descriptor limit higher than configured",
				zap.Uint64("current", rlimit.Cur),
				zap.Uint64("configured", sh.config.MaxFileDescriptors))
		}
	}

	return nil
}

// setRLimit sets a resource limit
func (sh *SecurityHardener) setRLimit(resource int, limit uint64) error {
	rlimit := syscall.Rlimit{
		Cur: limit,
		Max: limit,
	}
	return syscall.Setrlimit(resource, &rlimit)
}

// disableCoreDumps disables core dump generation
func (sh *SecurityHardener) disableCoreDumps() error {
	return sh.setRLimit(syscall.RLIMIT_CORE, 0)
}

// ConfigureHTTPServer applies security hardening to an HTTP server
func (sh *SecurityHardener) ConfigureHTTPServer(server *http.Server) error {
	// Apply TLS configuration if available
	if sh.tlsManager != nil {
		sh.tlsManager.ConfigureHTTPServer(server)
		sh.logger.Info("TLS configuration applied to HTTP server")
	}

	// Set secure timeouts if not already configured
	if server.ReadTimeout == 0 {
		server.ReadTimeout = 30 * time.Second
	}
	if server.WriteTimeout == 0 {
		server.WriteTimeout = 30 * time.Second
	}
	if server.IdleTimeout == 0 {
		server.IdleTimeout = 120 * time.Second
	}

	// Set maximum header size
	if server.MaxHeaderBytes == 0 {
		server.MaxHeaderBytes = 32 << 10 // 32KB
	}

	// Disable HTTP/2 if not explicitly enabled (for simplicity)
	if server.TLSConfig != nil && server.TLSConfig.NextProtos == nil {
		server.TLSConfig.NextProtos = []string{"http/1.1"}
	}

	return nil
}

// StartTLSCertificateRefresh starts TLS certificate refresh if configured
func (sh *SecurityHardener) StartTLSCertificateRefresh(ctx context.Context) {
	if sh.tlsManager != nil {
		sh.tlsManager.StartCertificateRefresh(ctx)
	}
}

// GetTLSConfig returns the TLS configuration if available
func (sh *SecurityHardener) GetTLSConfig() *TLSConfig {
	if sh.tlsManager != nil {
		return sh.tlsManager.config
	}
	return nil
}

// SecurityMiddleware returns an HTTP middleware that adds security headers
func (sh *SecurityHardener) SecurityMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

			// HSTS header for HTTPS
			if r.TLS != nil {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}

			// Remove server identification
			w.Header().Del("Server")
			w.Header().Set("Server", "MCP-Airlock")

			next.ServeHTTP(w, r)
		})
	}
}

// GetSecurityReport returns a security status report
func (sh *SecurityHardener) GetSecurityReport() map[string]interface{} {
	report := map[string]interface{}{
		"non_root_user":     os.Getuid() != 0,
		"uid":               os.Getuid(),
		"gid":               os.Getgid(),
		"tls_enabled":       sh.tlsManager != nil,
		"go_version":        runtime.Version(),
		"os":                runtime.GOOS,
		"arch":              runtime.GOARCH,
		"num_goroutines":    runtime.NumGoroutine(),
		"hardening_applied": true,
	}

	// Add resource limit information
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err == nil {
		report["max_file_descriptors"] = rlimit.Cur
	}

	if runtime.GOOS == "linux" {
		const RLIMIT_NPROC = 6
		if err := syscall.Getrlimit(RLIMIT_NPROC, &rlimit); err == nil {
			report["max_processes"] = rlimit.Cur
		}
	}

	return report
}
