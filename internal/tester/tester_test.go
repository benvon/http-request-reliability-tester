package tester

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/benvon/http-request-reliability-tester/internal/client"
	"github.com/benvon/http-request-reliability-tester/internal/config"
)

func TestNewTester(t *testing.T) {
	cfg := &config.Config{
		Endpoints:         []string{"https://example.com"},
		RequestsPerMinute: 60,
		Duration:          5 * time.Minute,
	}

	tester := New(cfg)

	if tester == nil {
		t.Fatal("Expected tester to be created")
	}

	if tester.config != cfg {
		t.Error("Expected config to be set")
	}

	if tester.client == nil {
		t.Error("Expected client to be created")
	}

	if tester.results == nil {
		t.Error("Expected results to be initialized")
	}
}

func TestProcessResult(t *testing.T) {
	cfg := &config.Config{
		Endpoints:         []string{"https://example.com"},
		RequestsPerMinute: 60,
		Duration:          5 * time.Minute,
	}

	tester := New(cfg)

	// Initialize endpoint result
	tester.results.EndpointResults["https://example.com"] = &EndpointResult{
		Endpoint:       "https://example.com",
		ErrorBreakdown: make(map[client.ErrorType]int),
	}

	// Test successful request
	successResult := &client.RequestResult{
		Endpoint:   "https://example.com",
		StatusCode: 200,
		Error:      nil,
		Duration:   100 * time.Millisecond,
	}

	tester.processResult(successResult)

	if tester.results.TotalRequests != 1 {
		t.Errorf("Expected 1 total request, got %d", tester.results.TotalRequests)
	}

	if tester.results.TotalErrors != 0 {
		t.Errorf("Expected 0 total errors, got %d", tester.results.TotalErrors)
	}

	endpointResult := tester.results.EndpointResults["https://example.com"]
	if endpointResult.TotalRequests != 1 {
		t.Errorf("Expected 1 endpoint request, got %d", endpointResult.TotalRequests)
	}

	if endpointResult.SuccessCount != 1 {
		t.Errorf("Expected 1 success, got %d", endpointResult.SuccessCount)
	}

	// Test failed request
	errorResult := &client.RequestResult{
		Endpoint:   "https://example.com",
		StatusCode: 500,
		Error:      &net.OpError{},
		ErrorType:  client.ErrorTypeConnection,
		Duration:   200 * time.Millisecond,
	}

	tester.processResult(errorResult)

	if tester.results.TotalRequests != 2 {
		t.Errorf("Expected 2 total requests, got %d", tester.results.TotalRequests)
	}

	if tester.results.TotalErrors != 1 {
		t.Errorf("Expected 1 total error, got %d", tester.results.TotalErrors)
	}

	if tester.results.ErrorBreakdown[client.ErrorTypeConnection] != 1 {
		t.Errorf("Expected 1 connection error, got %d", tester.results.ErrorBreakdown[client.ErrorTypeConnection])
	}
}

func TestShouldRemoveEndpoint(t *testing.T) {
	cfg := &config.Config{
		Endpoints:         []string{"https://example.com"},
		RequestsPerMinute: 60,
		Duration:          5 * time.Minute,
	}

	endpoint := "https://example.com"

	t.Run("removed after three consecutive HTTP errors", func(t *testing.T) {
		tester := New(cfg)
		tester.results.EndpointResults[endpoint] = &EndpointResult{
			Endpoint:       endpoint,
			ErrorBreakdown: make(map[client.ErrorType]int),
		}

		for i := 0; i < 3; i++ {
			tester.processResult(&client.RequestResult{
				Endpoint:   endpoint,
				StatusCode: 500,
				Error:      errors.New("server error"),
				ErrorType:  client.ErrorTypeHTTP,
			})
		}

		if !tester.shouldRemoveEndpoint(endpoint) {
			t.Error("Expected endpoint to be removed after 3 consecutive HTTP errors")
		}
	})

	t.Run("not removed when errors are not consecutive or not HTTP", func(t *testing.T) {
		tester := New(cfg)
		tester.results.EndpointResults[endpoint] = &EndpointResult{
			Endpoint:       endpoint,
			ErrorBreakdown: make(map[client.ErrorType]int),
		}

		tester.processResult(&client.RequestResult{
			Endpoint:   endpoint,
			StatusCode: 500,
			Error:      errors.New("server error"),
			ErrorType:  client.ErrorTypeHTTP,
		})
		tester.processResult(&client.RequestResult{
			Endpoint:   endpoint,
			StatusCode: 500,
			Error:      errors.New("server error"),
			ErrorType:  client.ErrorTypeHTTP,
		})
		tester.processResult(&client.RequestResult{
			Endpoint:   endpoint,
			StatusCode: 200,
			Error:      nil,
		})
		tester.processResult(&client.RequestResult{
			Endpoint:   endpoint,
			StatusCode: 500,
			Error:      errors.New("server error"),
			ErrorType:  client.ErrorTypeHTTP,
		})
		tester.processResult(&client.RequestResult{
			Endpoint:   endpoint,
			StatusCode: 500,
			Error:      errors.New("server error"),
			ErrorType:  client.ErrorTypeHTTP,
		})

		if tester.shouldRemoveEndpoint(endpoint) {
			t.Error("Expected endpoint not to be removed when success breaks error streak")
		}

		tester = New(cfg)
		tester.results.EndpointResults[endpoint] = &EndpointResult{
			Endpoint:       endpoint,
			ErrorBreakdown: make(map[client.ErrorType]int),
		}

		tester.processResult(&client.RequestResult{
			Endpoint:   endpoint,
			StatusCode: 500,
			Error:      errors.New("server error"),
			ErrorType:  client.ErrorTypeHTTP,
		})
		tester.processResult(&client.RequestResult{
			Endpoint:   endpoint,
			StatusCode: 500,
			Error:      errors.New("server error"),
			ErrorType:  client.ErrorTypeHTTP,
		})
		tester.processResult(&client.RequestResult{
			Endpoint:   endpoint,
			StatusCode: 0,
			Error:      errors.New("timeout"),
			ErrorType:  client.ErrorTypeTimeout,
		})
		tester.processResult(&client.RequestResult{
			Endpoint:   endpoint,
			StatusCode: 500,
			Error:      errors.New("server error"),
			ErrorType:  client.ErrorTypeHTTP,
		})
		tester.processResult(&client.RequestResult{
			Endpoint:   endpoint,
			StatusCode: 500,
			Error:      errors.New("server error"),
			ErrorType:  client.ErrorTypeHTTP,
		})

		if tester.shouldRemoveEndpoint(endpoint) {
			t.Error("Expected endpoint not to be removed when non-HTTP error breaks streak")
		}
	})
}

func TestGetResults(t *testing.T) {
	cfg := &config.Config{
		Endpoints:         []string{"https://example.com"},
		RequestsPerMinute: 60,
		Duration:          5 * time.Minute,
	}

	tester := New(cfg)

	// Initialize endpoint result
	tester.results.EndpointResults["https://example.com"] = &EndpointResult{
		Endpoint:       "https://example.com",
		ErrorBreakdown: make(map[client.ErrorType]int),
	}

	// Add some test data
	tester.results.TotalRequests = 10
	tester.results.TotalErrors = 2
	tester.results.ErrorBreakdown[client.ErrorTypeConnection] = 2
	tester.results.EndpointResults["https://example.com"].TotalRequests = 10
	tester.results.EndpointResults["https://example.com"].TotalErrors = 2

	results := tester.GetResults()

	if results.TotalRequests != 10 {
		t.Errorf("Expected 10 total requests, got %d", results.TotalRequests)
	}

	if results.TotalErrors != 2 {
		t.Errorf("Expected 2 total errors, got %d", results.TotalErrors)
	}

	if results.ErrorBreakdown[client.ErrorTypeConnection] != 2 {
		t.Errorf("Expected 2 connection errors, got %d", results.ErrorBreakdown[client.ErrorTypeConnection])
	}

	// Verify it's a deep copy
	results.TotalRequests = 999
	if tester.results.TotalRequests == 999 {
		t.Error("Expected deep copy, but original was modified")
	}
}

func TestRunWithContextCancellation(t *testing.T) {
	cfg := &config.Config{
		Endpoints:         []string{"https://httpbin.org"},
		RequestsPerMinute: 60,
		Duration:          1 * time.Second,
	}

	tester := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	results, err := tester.Run(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if results == nil {
		t.Fatal("Expected results to be returned")
	}

	// Should have minimal results since we cancelled immediately
	if results.TotalRequests > 5 {
		t.Errorf("Expected few requests due to immediate cancellation, got %d", results.TotalRequests)
	}
}
