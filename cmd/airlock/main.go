// Package main provides the entry point for MCP Airlock
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ik-labs/mcp-airlock/pkg/config"
	"github.com/ik-labs/mcp-airlock/pkg/health"
	"go.uber.org/zap"
)

var (
	configFile = flag.String("config", "config.yaml", "Path to configuration file")
	version    = flag.Bool("version", false, "Show version information")
)

// Version information (set by build process)
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("MCP Airlock %s (commit: %s, built: %s)\n", Version, GitCommit, BuildTime)
		os.Exit(0)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Initialize logger (development mode for now)
	logger, err := config.NewDevelopmentLogger()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("Starting MCP Airlock",
		zap.String("version", Version),
		zap.String("commit", GitCommit),
		zap.String("build_time", BuildTime),
		zap.String("config_file", *configFile),
	)

	// Load configuration
	loader := config.NewLoader()
	cfg, err := loader.LoadFromFile(*configFile)
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	logger.Info("Configuration loaded successfully",
		zap.String("server_addr", cfg.Server.Addr),
		zap.String("public_base_url", cfg.Server.PublicBaseURL),
		zap.Int("upstream_count", len(cfg.Upstreams)),
	)

	// Initialize health checker
	healthChecker := health.NewHealthChecker(logger)
	
	// Register default health checks
	defaultChecks := health.DefaultChecks(logger)
	for name, checkFunc := range defaultChecks {
		healthChecker.RegisterCheck(name, checkFunc)
	}

	// Register configuration-specific health checks
	healthChecker.RegisterCheck("config", func(ctx context.Context) (health.Status, string) {
		if cfg == nil {
			return health.StatusUnhealthy, "Configuration not loaded"
		}
		return health.StatusHealthy, "Configuration loaded and valid"
	})

	// Start periodic health checks
	go healthChecker.StartPeriodicChecks(ctx, 30*time.Second)

	// Set up HTTP server with health endpoints
	mux := http.NewServeMux()
	mux.HandleFunc("/live", healthChecker.LivenessHandler())
	mux.HandleFunc("/ready", healthChecker.ReadinessHandler())
	
	// Add a basic info endpoint
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"version":"%s","commit":"%s","build_time":"%s"}`, Version, GitCommit, BuildTime)
	})

	server := &http.Server{
		Addr:         cfg.Server.Addr,
		Handler:      mux,
		ReadTimeout:  cfg.Server.Timeouts.Read,
		WriteTimeout: cfg.Server.Timeouts.Write,
		IdleTimeout:  cfg.Server.Timeouts.Idle,
	}

	// Start server in a goroutine
	go func() {
		logger.Info("Starting HTTP server", zap.String("addr", cfg.Server.Addr))
		
		if cfg.Server.TLS.CertFile != "" && cfg.Server.TLS.KeyFile != "" {
			logger.Info("Starting HTTPS server with TLS")
			if err := server.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				logger.Fatal("HTTPS server failed", zap.Error(err))
			}
		} else {
			logger.Info("Starting HTTP server (no TLS)")
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Fatal("HTTP server failed", zap.Error(err))
			}
		}
	}()

	logger.Info("MCP Airlock started successfully")

	// Wait for shutdown signal
	<-sigChan
	logger.Info("Shutdown signal received, starting graceful shutdown")

	// Cancel context to stop background tasks
	cancel()

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server shutdown failed", zap.Error(err))
	} else {
		logger.Info("Server shutdown completed")
	}

	logger.Info("MCP Airlock stopped")
}