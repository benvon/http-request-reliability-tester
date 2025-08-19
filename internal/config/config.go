package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// OutputFormat represents the supported output formats
type OutputFormat string

const (
	OutputFormatMarkdown OutputFormat = "markdown"
	OutputFormatJSON     OutputFormat = "json"
	OutputFormatCSV      OutputFormat = "csv"
)

// Config holds all configuration options
type Config struct {
	Endpoints         []string
	Duration          time.Duration
	RequestCount      int
	Continuous        bool
	RequestsPerMinute int
	HighRateMode      bool
	OutputFormat      OutputFormat
	OutputFile        string
	Debug             bool
}

// Default endpoints as specified in requirements
var defaultEndpoints = []string{
	"https://httpbin.org",
	"https://postman-echo.com",
	"https://run.mocky.io",
	"https://jsonplaceholder.typicode.com",
	"https://httpbingo.org",
	"https://beeceptor.com",
	"https://requestbin.com",
	"https://webhook.site",
	"https://hookbin.com",
	"https://httpstat.us",
	"https://mocki.io",
}

// Load loads configuration with proper precedence:
// 1. Environment variables (highest)
// 2. Command line flags
// 3. Configuration file (lowest)
func Load(fs *flag.FlagSet, args []string) (*Config, error) {
	cfg := &Config{
		Endpoints:         defaultEndpoints,
		Duration:          5 * time.Minute,
		RequestCount:      0,
		Continuous:        false,
		RequestsPerMinute: 60,
		HighRateMode:      false,
		OutputFormat:      OutputFormatMarkdown,
		OutputFile:        "",
		Debug:             false,
	}

	// Parse command line flags
	parseFlags(cfg, fs, args)

	// Apply environment variables (highest precedence)
	if err := applyEnvVars(cfg); err != nil {
		return nil, fmt.Errorf("failed to apply environment variables: %w", err)
	}

	return cfg, nil
}

// parseFlags parses command line flags using the provided FlagSet
func parseFlags(cfg *Config, fs *flag.FlagSet, args []string) {
	var endpoints string
	var duration string
	var outputFormat string

	fs.StringVar(&endpoints, "endpoints", "", "Comma-separated list of endpoints to test")
	fs.StringVar(&duration, "duration", "", "Test duration (e.g., '5m', '30s')")
	fs.IntVar(&cfg.RequestCount, "count", 0, "Total number of requests to send (0 for duration-based)")
	fs.BoolVar(&cfg.Continuous, "continuous", false, "Run continuously until interrupted")
	fs.IntVar(&cfg.RequestsPerMinute, "rate", 60, "Requests per minute")
	fs.BoolVar(&cfg.HighRateMode, "high-rate", false, "Allow rates exceeding 60 requests per minute")
	fs.StringVar(&outputFormat, "output", "markdown", "Output format: markdown, json, csv")
	fs.StringVar(&cfg.OutputFile, "output-file", "", "Output file path (default: stdout)")
	fs.BoolVar(&cfg.Debug, "debug", false, "Enable debug mode for extended error details")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Apply flag values
	if endpoints != "" {
		cfg.Endpoints = strings.Split(endpoints, ",")
		for i, endpoint := range cfg.Endpoints {
			cfg.Endpoints[i] = strings.TrimSpace(endpoint)
		}
	}

	if duration != "" {
		if d, err := time.ParseDuration(duration); err == nil {
			cfg.Duration = d
		}
	}

	if outputFormat != "" {
		cfg.OutputFormat = OutputFormat(outputFormat)
	}
}

// applyEnvVars applies environment variables with highest precedence
func applyEnvVars(cfg *Config) error {
	if endpoints := os.Getenv("HTTP_TESTER_ENDPOINTS"); endpoints != "" {
		cfg.Endpoints = strings.Split(endpoints, ",")
		for i, endpoint := range cfg.Endpoints {
			cfg.Endpoints[i] = strings.TrimSpace(endpoint)
		}
	}

	if duration := os.Getenv("HTTP_TESTER_DURATION"); duration != "" {
		if d, err := time.ParseDuration(duration); err == nil {
			cfg.Duration = d
		}
	}

	if count := os.Getenv("HTTP_TESTER_COUNT"); count != "" {
		if c, err := strconv.Atoi(count); err == nil {
			cfg.RequestCount = c
		}
	}

	if continuous := os.Getenv("HTTP_TESTER_CONTINUOUS"); continuous != "" {
		cfg.Continuous = strings.ToLower(continuous) == "true"
	}

	if rate := os.Getenv("HTTP_TESTER_RATE"); rate != "" {
		if r, err := strconv.Atoi(rate); err == nil {
			cfg.RequestsPerMinute = r
		}
	}

	if highRate := os.Getenv("HTTP_TESTER_HIGH_RATE"); highRate != "" {
		cfg.HighRateMode = strings.ToLower(highRate) == "true"
	}

	if outputFormat := os.Getenv("HTTP_TESTER_OUTPUT"); outputFormat != "" {
		cfg.OutputFormat = OutputFormat(outputFormat)
	}

	if outputFile := os.Getenv("HTTP_TESTER_OUTPUT_FILE"); outputFile != "" {
		cfg.OutputFile = outputFile
	}

	if debug := os.Getenv("HTTP_TESTER_DEBUG"); debug != "" {
		cfg.Debug = strings.ToLower(debug) == "true"
	}

	return nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if len(c.Endpoints) == 0 {
		return fmt.Errorf("no endpoints specified")
	}

	if c.RequestsPerMinute > 60 && !c.HighRateMode {
		return fmt.Errorf("requests per minute (%d) exceeds 60, use --high-rate flag to allow this", c.RequestsPerMinute)
	}

	if c.RequestsPerMinute <= 0 {
		return fmt.Errorf("requests per minute must be positive")
	}

	if !c.Continuous && c.RequestCount == 0 && c.Duration <= 0 {
		return fmt.Errorf("must specify either continuous mode, request count, or duration")
	}

	switch c.OutputFormat {
	case OutputFormatMarkdown, OutputFormatJSON, OutputFormatCSV:
		// Valid format
	default:
		return fmt.Errorf("invalid output format: %s", c.OutputFormat)
	}

	return nil
}
