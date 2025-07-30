package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/benvon/http-request-reliability-tester/internal/config"
	"github.com/benvon/http-request-reliability-tester/internal/output"
	"github.com/benvon/http-request-reliability-tester/internal/tester"
)

func main() {
	// Load configuration with proper precedence
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("configuration error: failed to load configuration - %v", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatalf("configuration error: validation failed - %v", err)
	}

	// Create context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal, shutting down gracefully...")
		cancel()
	}()

	// Create and run the tester
	t := tester.New(cfg)

	// Run the test
	results, err := t.Run(ctx)
	if err != nil {
		log.Fatalf("test execution error: %v", err)
	}

	// Output results
	if err := output.Write(results, cfg.OutputFormat, cfg.OutputFile); err != nil {
		log.Fatalf("output error: failed to write results - %v", err)
	}
}
