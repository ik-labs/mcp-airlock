// Package config provides logging configuration and setup
package config

import (
	"fmt"

	"go.uber.org/zap"
)

// LoggerConfig contains logger-specific configuration
type LoggerConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	OutputPath string `yaml:"output_path"`
}

// NewLogger creates a new structured logger based on configuration
func NewLogger(config LoggingConfig) (*zap.Logger, error) {
	var zapConfig zap.Config
	
	// Set up base configuration based on format
	switch config.Format {
	case "json", "":
		zapConfig = zap.NewProductionConfig()
	case "text":
		zapConfig = zap.NewDevelopmentConfig()
	default:
		return nil, fmt.Errorf("unsupported log format: %s", config.Format)
	}
	
	// Set log level
	level, err := zap.ParseAtomicLevel(config.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level %s: %w", config.Level, err)
	}
	zapConfig.Level = level
	
	// Configure structured fields for production logging
	if config.Format == "json" {
		zapConfig.EncoderConfig.TimeKey = "timestamp"
		zapConfig.EncoderConfig.LevelKey = "level"
		zapConfig.EncoderConfig.MessageKey = "message"
		zapConfig.EncoderConfig.CallerKey = "caller"
		zapConfig.EncoderConfig.StacktraceKey = "stacktrace"
	}
	
	// Build the logger
	logger, err := zapConfig.Build(
		zap.AddCaller(),
		zap.AddStacktrace(zap.ErrorLevel),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build logger: %w", err)
	}
	
	return logger, nil
}

// NewDevelopmentLogger creates a development logger with console output
func NewDevelopmentLogger() (*zap.Logger, error) {
	config := zap.NewDevelopmentConfig()
	config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	
	logger, err := config.Build(
		zap.AddCaller(),
		zap.AddStacktrace(zap.ErrorLevel),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build development logger: %w", err)
	}
	
	return logger, nil
}

// NewProductionLogger creates a production logger with JSON output
func NewProductionLogger() (*zap.Logger, error) {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	
	logger, err := config.Build(
		zap.AddCaller(),
		zap.AddStacktrace(zap.ErrorLevel),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build production logger: %w", err)
	}
	
	return logger, nil
}