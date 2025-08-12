// Package config provides configuration management for MCP Airlock
package config

import (
	"fmt"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Config represents the complete application configuration
type Config struct {
	Server        ServerConfig        `mapstructure:"server"`
	Auth          AuthConfig          `mapstructure:"auth"`
	Policy        PolicyConfig        `mapstructure:"policy"`
	Roots         []RootConfig        `mapstructure:"roots"`
	DLP           DLPConfig           `mapstructure:"dlp"`
	RateLimiting  RateLimitingConfig  `mapstructure:"rate_limiting"`
	Upstreams     []UpstreamConfig    `mapstructure:"upstreams"`
	Audit         AuditConfig         `mapstructure:"audit"`
	Observability ObservabilityConfig `mapstructure:"observability"`
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Addr          string        `mapstructure:"addr"`
	PublicBaseURL string        `mapstructure:"public_base_url"`
	TLS           TLSConfig     `mapstructure:"tls"`
	Timeouts      TimeoutConfig `mapstructure:"timeouts"`
}

// TLSConfig contains TLS configuration
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// TimeoutConfig contains server timeout configuration
type TimeoutConfig struct {
	Read     time.Duration `yaml:"read" validate:"required"`
	Write    time.Duration `yaml:"write" validate:"required"`
	Idle     time.Duration `yaml:"idle" validate:"required"`
	Connect  time.Duration `yaml:"connect"`  // Connection timeout (default 2s)
	Upstream time.Duration `yaml:"upstream"` // Upstream call timeout (default 30s)
}

// AuthConfig contains authentication configuration
type AuthConfig struct {
	OIDCIssuer     string        `mapstructure:"oidc_issuer"`
	Audience       string        `mapstructure:"audience"`
	JWKSCacheTTL   time.Duration `mapstructure:"jwks_cache_ttl"`
	ClockSkew      time.Duration `mapstructure:"clock_skew"`
	RequiredGroups []string      `mapstructure:"required_groups"`
}

// PolicyConfig contains policy engine configuration
type PolicyConfig struct {
	RegoFile     string        `yaml:"rego_file" validate:"required"`
	CacheTTL     time.Duration `yaml:"cache_ttl" validate:"required"`
	ReloadSignal string        `yaml:"reload_signal"`
}

// RootConfig contains virtual root mapping configuration
type RootConfig struct {
	Name     string `yaml:"name" validate:"required"`
	Type     string `yaml:"type" validate:"required,oneof=fs s3"`
	Virtual  string `yaml:"virtual" validate:"required"`
	Real     string `yaml:"real" validate:"required"`
	ReadOnly bool   `yaml:"read_only"`
}

// DLPConfig contains data loss prevention configuration
type DLPConfig struct {
	Patterns []PatternConfig `yaml:"patterns"`
}

// PatternConfig contains redaction pattern configuration
type PatternConfig struct {
	Name    string   `yaml:"name" validate:"required"`
	Regex   string   `yaml:"regex" validate:"required"`
	Replace string   `yaml:"replace" validate:"required"`
	Fields  []string `yaml:"fields"`
}

// RateLimitingConfig contains rate limiting configuration
type RateLimitingConfig struct {
	PerToken string `yaml:"per_token" validate:"required"`
	PerIP    string `yaml:"per_ip" validate:"required"`
	Burst    int    `yaml:"burst" validate:"min=1"`
}

// UpstreamConfig contains upstream MCP server configuration
type UpstreamConfig struct {
	Name           string            `yaml:"name" validate:"required"`
	Type           string            `yaml:"type" validate:"required,oneof=stdio unix http"`
	Command        []string          `yaml:"command"`
	Socket         string            `yaml:"socket"`
	URL            string            `yaml:"url"`
	Env            map[string]string `yaml:"env"`
	Timeout        time.Duration     `yaml:"timeout" validate:"required"`
	ConnectTimeout time.Duration     `yaml:"connect_timeout"`
	AllowTools     []string          `yaml:"allow_tools"`
}

// AuditConfig contains audit logging configuration
type AuditConfig struct {
	Backend      string        `yaml:"backend" validate:"required,oneof=sqlite postgresql"`
	Database     string        `yaml:"database" validate:"required"`
	Retention    time.Duration `yaml:"retention" validate:"required"`
	ExportFormat string        `yaml:"export_format" validate:"oneof=jsonl json"`
}

// ObservabilityConfig contains observability configuration
type ObservabilityConfig struct {
	Metrics MetricsConfig `yaml:"metrics"`
	Tracing TracingConfig `yaml:"tracing"`
	Logging LoggingConfig `yaml:"logging"`
}

// MetricsConfig contains metrics configuration
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// TracingConfig contains tracing configuration
type TracingConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level" validate:"oneof=debug info warn error"`
	Format string `yaml:"format" validate:"oneof=json text"`
}

// Loader handles configuration loading and validation
type Loader struct {
	k *koanf.Koanf
}

// NewLoader creates a new configuration loader
func NewLoader() *Loader {
	return &Loader{
		k: koanf.New("."),
	}
}

// LoadFromFile loads configuration from a YAML file
func (l *Loader) LoadFromFile(path string) (*Config, error) {
	// Load the YAML file
	if err := l.k.Load(file.Provider(path), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("failed to load config file %s: %w", path, err)
	}

	// Unmarshal into config struct
	var config Config
	if err := l.k.Unmarshal("", &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := l.validate(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

// validate performs basic configuration validation
func (l *Loader) validate(config *Config) error {
	// For now, just do minimal validation to get the scaffolding working
	// More comprehensive validation will be added in later tasks

	if config.Server.Addr == "" {
		return fmt.Errorf("server.addr is required")
	}

	// Skip other validations for now to get the basic server running
	return nil
}

// GetString returns a string configuration value
func (l *Loader) GetString(key string) string {
	return l.k.String(key)
}

// GetInt returns an integer configuration value
func (l *Loader) GetInt(key string) int {
	return l.k.Int(key)
}

// GetBool returns a boolean configuration value
func (l *Loader) GetBool(key string) bool {
	return l.k.Bool(key)
}

// GetDuration returns a duration configuration value
func (l *Loader) GetDuration(key string) time.Duration {
	return l.k.Duration(key)
}
