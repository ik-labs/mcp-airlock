// Package config provides configuration management for MCP Airlock
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	yamlv3 "gopkg.in/yaml.v3"
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
	Addr          string        `mapstructure:"addr" validate:"required"`
	PublicBaseURL string        `mapstructure:"public_base_url" validate:"omitempty,url"`
	TLS           TLSConfig     `mapstructure:"tls"`
	Timeouts      TimeoutConfig `mapstructure:"timeouts"`
}

// TLSConfig contains TLS configuration
type TLSConfig struct {
	CertFile string `mapstructure:"cert_file" validate:"omitempty,file"`
	KeyFile  string `mapstructure:"key_file" validate:"omitempty,file"`
}

// TimeoutConfig contains server timeout configuration
type TimeoutConfig struct {
	Read     time.Duration `mapstructure:"read" validate:"omitempty"`
	Write    time.Duration `mapstructure:"write" validate:"omitempty"`
	Idle     time.Duration `mapstructure:"idle" validate:"omitempty"`
	Connect  time.Duration `mapstructure:"connect"`  // Connection timeout (default 2s)
	Upstream time.Duration `mapstructure:"upstream"` // Upstream call timeout (default 30s)
}

// AuthConfig contains authentication configuration
type AuthConfig struct {
	OIDCIssuer     string        `mapstructure:"oidc_issuer" validate:"omitempty,url"`
	Audience       string        `mapstructure:"audience" validate:"omitempty"`
	JWKSCacheTTL   time.Duration `mapstructure:"jwks_cache_ttl" validate:"omitempty,min=1m,max=1h"`
	ClockSkew      time.Duration `mapstructure:"clock_skew" validate:"omitempty,min=30s,max=10m"`
	RequiredGroups []string      `mapstructure:"required_groups" validate:"omitempty,min=1"`
}

// PolicyConfig contains policy engine configuration
type PolicyConfig struct {
	RegoFile     string        `mapstructure:"rego_file" validate:"omitempty"`
	CacheTTL     time.Duration `mapstructure:"cache_ttl" validate:"omitempty"`
	ReloadSignal string        `mapstructure:"reload_signal"`
}

// RootConfig contains virtual root mapping configuration
type RootConfig struct {
	Name     string `mapstructure:"name" validate:"required"`
	Type     string `mapstructure:"type" validate:"required,oneof=fs s3"`
	Virtual  string `mapstructure:"virtual" validate:"required"`
	Real     string `mapstructure:"real" validate:"required"`
	ReadOnly bool   `mapstructure:"read_only"`
}

// DLPConfig contains data loss prevention configuration
type DLPConfig struct {
	Patterns []PatternConfig `mapstructure:"patterns"`
}

// PatternConfig contains redaction pattern configuration
type PatternConfig struct {
	Name    string   `mapstructure:"name" validate:"required"`
	Regex   string   `mapstructure:"regex" validate:"required"`
	Replace string   `mapstructure:"replace" validate:"required"`
	Fields  []string `mapstructure:"fields"`
}

// RateLimitingConfig contains rate limiting configuration
type RateLimitingConfig struct {
	PerToken string `mapstructure:"per_token" validate:"omitempty"`
	PerIP    string `mapstructure:"per_ip" validate:"omitempty"`
	Burst    int    `mapstructure:"burst" validate:"omitempty,min=1"`
}

// UpstreamConfig contains upstream MCP server configuration
type UpstreamConfig struct {
	Name           string            `mapstructure:"name" validate:"required"`
	Type           string            `mapstructure:"type" validate:"required,oneof=stdio unix http"`
	Command        []string          `mapstructure:"command"`
	Socket         string            `mapstructure:"socket"`
	URL            string            `mapstructure:"url"`
	Env            map[string]string `mapstructure:"env"`
	Timeout        time.Duration     `mapstructure:"timeout" validate:"required"`
	ConnectTimeout time.Duration     `mapstructure:"connect_timeout"`
	AllowTools     []string          `mapstructure:"allow_tools"`
}

// AuditConfig contains audit logging configuration
type AuditConfig struct {
	Backend      string        `mapstructure:"backend" validate:"omitempty,oneof=sqlite postgresql"`
	Database     string        `mapstructure:"database" validate:"omitempty"`
	Retention    time.Duration `mapstructure:"retention" validate:"omitempty"`
	ExportFormat string        `mapstructure:"export_format" validate:"omitempty,oneof=jsonl json"`
}

// ObservabilityConfig contains observability configuration
type ObservabilityConfig struct {
	Metrics MetricsConfig `mapstructure:"metrics"`
	Tracing TracingConfig `mapstructure:"tracing"`
	Logging LoggingConfig `mapstructure:"logging"`
}

// MetricsConfig contains metrics configuration
type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
}

// TracingConfig contains tracing configuration
type TracingConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Endpoint string `mapstructure:"endpoint"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level  string `mapstructure:"level" validate:"omitempty,oneof=debug info warn error"`
	Format string `mapstructure:"format" validate:"omitempty,oneof=json text"`
}

// Loader handles configuration loading and validation
type Loader struct {
	k         *koanf.Koanf
	validator *validator.Validate
}

// ValidationError represents a configuration validation error with line information
type ValidationError struct {
	Field   string `json:"field"`
	Tag     string `json:"tag"`
	Value   string `json:"value"`
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
}

func (ve ValidationError) Error() string {
	if ve.Line > 0 {
		return fmt.Sprintf("line %d: %s", ve.Line, ve.Message)
	}
	return ve.Message
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	var messages []string
	for _, err := range ve {
		messages = append(messages, err.Error())
	}
	return strings.Join(messages, "; ")
}

// NewLoader creates a new configuration loader
func NewLoader() *Loader {
	v := validator.New()

	// Register custom validators
	v.RegisterValidation("file", validateFileExists)
	v.RegisterValidation("dir", validateDirExists)

	return &Loader{
		k:         koanf.New("."),
		validator: v,
	}
}

// validateFileExists checks if a file exists (for non-empty values)
func validateFileExists(fl validator.FieldLevel) bool {
	path := fl.Field().String()
	if path == "" {
		return true // Allow empty values for optional fields
	}
	_, err := os.Stat(path)
	return err == nil
}

// validateDirExists checks if a directory exists (for non-empty values)
func validateDirExists(fl validator.FieldLevel) bool {
	path := fl.Field().String()
	if path == "" {
		return true // Allow empty values for optional fields
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// LoadFromFile loads configuration from a YAML file with environment variable support
func (l *Loader) LoadFromFile(path string) (*Config, error) {
	// Load the YAML file first
	if err := l.k.Load(file.Provider(path), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("failed to load config file %s: %w", path, err)
	}

	// Load environment variables (overrides file values)
	if err := l.k.Load(env.Provider("AIRLOCK_", ".", func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, "AIRLOCK_")), "_", ".", -1)
	}), nil); err != nil {
		return nil, fmt.Errorf("failed to load environment variables: %w", err)
	}

	// Load secrets from mounted files if specified
	if err := l.LoadSecrets(); err != nil {
		return nil, fmt.Errorf("failed to load secrets: %w", err)
	}

	// Unmarshal into config struct using UnmarshalWithConf for better control
	var config Config
	if err := l.k.UnmarshalWithConf("", &config, koanf.UnmarshalConf{Tag: "mapstructure"}); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration with line number information
	if err := l.validateWithLineNumbers(&config, path); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

// LoadSecrets loads sensitive configuration from mounted secret files
func (l *Loader) LoadSecrets() error {
	secretMounts := map[string]string{
		"auth.oidc_client_secret": "/var/secrets/oidc-client-secret",
		"server.tls.cert_file":    "/var/secrets/tls-cert",
		"server.tls.key_file":     "/var/secrets/tls-key",
	}

	for key, path := range secretMounts {
		if _, err := os.Stat(path); err == nil {
			content, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read secret file %s: %w", path, err)
			}
			l.k.Set(key, strings.TrimSpace(string(content)))
		}
	}

	return nil
}

// validateWithLineNumbers performs comprehensive configuration validation with line number information
func (l *Loader) validateWithLineNumbers(config *Config, configPath string) error {
	// First, perform struct validation
	if err := l.validator.Struct(config); err != nil {
		var validationErrors ValidationErrors

		// Parse YAML to get line numbers for better error reporting
		var yamlNode yamlv3.Node
		if configPath != "" {
			if yamlData, err := os.ReadFile(configPath); err == nil {
				yamlv3.Unmarshal(yamlData, &yamlNode)
			}
		}

		for _, err := range err.(validator.ValidationErrors) {
			ve := ValidationError{
				Field:   err.Field(),
				Tag:     err.Tag(),
				Value:   fmt.Sprintf("%v", err.Value()),
				Message: l.formatValidationMessage(err),
			}

			// Try to find line number in YAML
			if line := l.findLineNumber(&yamlNode, err.Namespace()); line > 0 {
				ve.Line = line
			}

			validationErrors = append(validationErrors, ve)
		}

		return validationErrors
	}

	// Perform custom business logic validation
	if err := l.validateBusinessRules(config); err != nil {
		return err
	}

	return nil
}

// formatValidationMessage creates human-readable validation error messages
func (l *Loader) formatValidationMessage(err validator.FieldError) string {
	field := err.Field()
	tag := err.Tag()
	value := fmt.Sprintf("%v", err.Value())

	switch tag {
	case "required":
		return fmt.Sprintf("field '%s' is required", field)
	case "url":
		return fmt.Sprintf("field '%s' must be a valid URL, got '%s'", field, value)
	case "file":
		return fmt.Sprintf("field '%s' must be a valid file path, got '%s'", field, value)
	case "dir":
		return fmt.Sprintf("field '%s' must be a valid directory path, got '%s'", field, value)
	case "min":
		return fmt.Sprintf("field '%s' must be at least %s, got '%s'", field, err.Param(), value)
	case "max":
		return fmt.Sprintf("field '%s' must be at most %s, got '%s'", field, err.Param(), value)
	case "oneof":
		return fmt.Sprintf("field '%s' must be one of [%s], got '%s'", field, err.Param(), value)
	default:
		return fmt.Sprintf("field '%s' failed validation '%s' with value '%s'", field, tag, value)
	}
}

// findLineNumber attempts to find the line number for a field in the YAML
func (l *Loader) findLineNumber(node *yamlv3.Node, namespace string) int {
	// This is a simplified implementation - in a production system,
	// you might want to use a more sophisticated YAML parser that preserves
	// line number information throughout the parsing process
	if node == nil {
		return 0
	}

	// For now, return 0 to indicate line number not available
	// A full implementation would traverse the YAML node tree
	return 0
}

// validateBusinessRules performs custom business logic validation
func (l *Loader) validateBusinessRules(config *Config) error {
	var errors []string

	// Validate TLS configuration consistency
	if (config.Server.TLS.CertFile == "") != (config.Server.TLS.KeyFile == "") {
		errors = append(errors, "both tls.cert_file and tls.key_file must be specified together or both empty")
	}

	// Validate upstream configurations
	for i, upstream := range config.Upstreams {
		if err := l.validateUpstream(&upstream, i); err != nil {
			errors = append(errors, err.Error())
		}
	}

	// Validate root configurations
	for i, root := range config.Roots {
		if err := l.validateRoot(&root, i); err != nil {
			errors = append(errors, err.Error())
		}
	}

	// Validate DLP patterns
	for i, pattern := range config.DLP.Patterns {
		if err := l.validateDLPPattern(&pattern, i); err != nil {
			errors = append(errors, err.Error())
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("business rule validation failed: %s", strings.Join(errors, "; "))
	}

	return nil
}

// validateUpstream validates upstream configuration
func (l *Loader) validateUpstream(upstream *UpstreamConfig, index int) error {
	prefix := fmt.Sprintf("upstreams[%d]", index)

	switch upstream.Type {
	case "stdio":
		if len(upstream.Command) == 0 {
			return fmt.Errorf("%s: command is required for stdio type", prefix)
		}
	case "unix":
		if upstream.Socket == "" {
			return fmt.Errorf("%s: socket is required for unix type", prefix)
		}
	case "http":
		if upstream.URL == "" {
			return fmt.Errorf("%s: url is required for http type", prefix)
		}
	default:
		return fmt.Errorf("%s: invalid type '%s', must be one of: stdio, unix, http", prefix, upstream.Type)
	}

	return nil
}

// validateRoot validates root configuration
func (l *Loader) validateRoot(root *RootConfig, index int) error {
	prefix := fmt.Sprintf("roots[%d]", index)

	if !strings.HasPrefix(root.Virtual, "mcp://") {
		return fmt.Errorf("%s: virtual path must start with 'mcp://', got '%s'", prefix, root.Virtual)
	}

	switch root.Type {
	case "fs":
		if !strings.HasPrefix(root.Real, "/") {
			return fmt.Errorf("%s: filesystem real path must be absolute, got '%s'", prefix, root.Real)
		}
	case "s3":
		if !strings.HasPrefix(root.Real, "s3://") {
			return fmt.Errorf("%s: S3 real path must start with 's3://', got '%s'", prefix, root.Real)
		}
	default:
		return fmt.Errorf("%s: invalid type '%s', must be one of: fs, s3", prefix, root.Type)
	}

	return nil
}

// validateDLPPattern validates DLP pattern configuration
func (l *Loader) validateDLPPattern(pattern *PatternConfig, index int) error {
	prefix := fmt.Sprintf("dlp.patterns[%d]", index)

	// Test regex compilation
	if _, err := regexp.Compile(pattern.Regex); err != nil {
		return fmt.Errorf("%s: invalid regex pattern '%s': %w", prefix, pattern.Regex, err)
	}

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
