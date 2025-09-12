// Package main provides the entry point for MCP Airlock
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ik-labs/mcp-airlock/internal/server"
	"github.com/ik-labs/mcp-airlock/pkg/config"
	"github.com/ik-labs/mcp-airlock/pkg/health"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// Version information (set by build process)
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

var (
	configFile string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "airlock",
		Short: "MCP Airlock - Secure MCP proxy with authentication and authorization",
		Long:  "MCP Airlock provides secure access to Model Context Protocol servers with authentication, authorization, and audit logging.",
		RunE:  runServer,
	}

	// Add global flags
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "config.yaml", "Path to configuration file")
	rootCmd.Flags().Bool("version", false, "Show version information")

	// Add version command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("MCP Airlock %s (commit: %s, built: %s)\n", Version, GitCommit, BuildTime)
		},
	}
	rootCmd.AddCommand(versionCmd)

	// Add performance commands
	addPerformanceCommands(rootCmd)

	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		_, err := fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		if err != nil {
			return
		}
		os.Exit(1)
	}
}

func runServer(cmd *cobra.Command, _ []string) error {
	// Check if version flag was used
	if versionFlag, _ := cmd.Flags().GetBool("version"); versionFlag {
		fmt.Printf("MCP Airlock %s (commit: %s, built: %s)\n", Version, GitCommit, BuildTime)
		return nil
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
		_, err := fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		if err != nil {
			return err
		}
		os.Exit(1)
	}
	defer func(logger *zap.Logger) {
		err := logger.Sync()
		if err != nil {
			// Ignore sync errors on shutdown
		}
	}(logger)

	logger.Info("Starting MCP Airlock",
		zap.String("version", Version),
		zap.String("commit", GitCommit),
		zap.String("build_time", BuildTime),
		zap.String("config_file", configFile),
	)

	// Load configuration
	loader := config.NewLoader()
	cfg, err := loader.LoadFromFile(configFile)
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

	// Create server configuration
	serverConfig := &server.Config{
		Addr:              cfg.Server.Addr,
		ReadTimeout:       cfg.Server.Timeouts.Read,
		WriteTimeout:      cfg.Server.Timeouts.Write,
		IdleTimeout:       cfg.Server.Timeouts.Idle,
		HeartbeatInterval: 20 * time.Second,
		MaxMessageSize:    256 * 1024, // 256KB
		MaxQueueSize:      1000,
		MaxConnections:    1000,
		MaxClients:        100,
		ConnectTimeout:    2 * time.Second,
		UpstreamTimeout:   30 * time.Second,
	}

	// Create the full MCP Airlock server
	airlockServer := server.NewAirlockServer(logger, serverConfig)

	// Set up health checker (skip for now due to interface mismatch)
	// TODO: Create adapter for health checker interface
	// if healthChecker != nil {
	//     airlockServer.SetHealthChecker(healthChecker)
	// }

	// Add upstream configurations
	for _, upstream := range cfg.Upstreams {
		upstreamConfig := &server.UpstreamConfig{
			Name:       upstream.Name,
			Type:       upstream.Type,
			Command:    upstream.Command,
			Socket:     upstream.Socket,
			Env:        upstream.Env,
			Timeout:    upstream.Timeout,
			AllowTools: upstream.AllowTools,
		}

		if err := airlockServer.AddUpstream(upstreamConfig); err != nil {
			logger.Error("Failed to add upstream", zap.String("name", upstream.Name), zap.Error(err))
		} else {
			logger.Info("Added upstream", zap.String("name", upstream.Name), zap.String("type", upstream.Type))
		}
	}

	// Start the full MCP Airlock server
	if err := airlockServer.Start(ctx); err != nil {
		logger.Fatal("Failed to start MCP Airlock server", zap.Error(err))
	}

	logger.Info("MCP Airlock started successfully")

	// Wait for shutdown signal
	<-sigChan
	logger.Info("Shutdown signal received, starting graceful shutdown")

	// Cancel context to stop background tasks
	cancel()

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := airlockServer.Stop(shutdownCtx); err != nil {
		logger.Error("Server shutdown failed", zap.Error(err))
	} else {
		logger.Info("Server shutdown completed")
	}

	logger.Info("MCP Airlock stopped")
	return nil
}
