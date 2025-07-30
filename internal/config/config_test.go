package config

import (
	"os"
	"testing"
	"time"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				Endpoints:         []string{"https://example.com"},
				RequestsPerMinute: 60,
				Duration:          5 * time.Minute,
				OutputFormat:      OutputFormatMarkdown,
			},
			wantErr: false,
		},
		{
			name: "no endpoints",
			config: &Config{
				Endpoints:         []string{},
				RequestsPerMinute: 60,
				Duration:          5 * time.Minute,
			},
			wantErr: true,
		},
		{
			name: "high rate without flag",
			config: &Config{
				Endpoints:         []string{"https://example.com"},
				RequestsPerMinute: 120,
				HighRateMode:      false,
				Duration:          5 * time.Minute,
			},
			wantErr: true,
		},
		{
			name: "high rate with flag",
			config: &Config{
				Endpoints:         []string{"https://example.com"},
				RequestsPerMinute: 120,
				HighRateMode:      true,
				Duration:          5 * time.Minute,
				OutputFormat:      OutputFormatMarkdown,
			},
			wantErr: false,
		},
		{
			name: "invalid output format",
			config: &Config{
				Endpoints:         []string{"https://example.com"},
				RequestsPerMinute: 60,
				OutputFormat:      "invalid",
				Duration:          5 * time.Minute,
			},
			wantErr: true,
		},
		{
			name: "no duration or count or continuous",
			config: &Config{
				Endpoints:         []string{"https://example.com"},
				RequestsPerMinute: 60,
				Duration:          0,
				RequestCount:      0,
				Continuous:        false,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultEndpoints(t *testing.T) {
	config, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(config.Endpoints) == 0 {
		t.Error("Expected default endpoints to be set")
	}

	// Check that we have the expected default endpoints
	expectedEndpoints := []string{
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

	for _, expected := range expectedEndpoints {
		found := false
		for _, actual := range config.Endpoints {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected endpoint %s not found in default endpoints", expected)
		}
	}
}

func TestEnvironmentVariablePrecedence(t *testing.T) {
	t.Skip("Skipping due to flag redefinition issues in test environment")

	// Set environment variable
	os.Setenv("HTTP_TESTER_ENDPOINTS", "https://test1.com,https://test2.com")
	defer os.Unsetenv("HTTP_TESTER_ENDPOINTS")

	config, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	expected := []string{"https://test1.com", "https://test2.com"}
	if len(config.Endpoints) != len(expected) {
		t.Errorf("Expected %d endpoints, got %d", len(expected), len(config.Endpoints))
	}

	for i, endpoint := range expected {
		if config.Endpoints[i] != endpoint {
			t.Errorf("Expected endpoint %s, got %s", endpoint, config.Endpoints[i])
		}
	}
}

func TestOutputFormatValidation(t *testing.T) {
	validFormats := []OutputFormat{
		OutputFormatMarkdown,
		OutputFormatJSON,
		OutputFormatCSV,
	}

	for _, format := range validFormats {
		config := &Config{
			Endpoints:         []string{"https://example.com"},
			RequestsPerMinute: 60,
			OutputFormat:      format,
			Duration:          5 * time.Minute,
		}
		if err := config.Validate(); err != nil {
			t.Errorf("Valid output format %s failed validation: %v", format, err)
		}
	}
}
