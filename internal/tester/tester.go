package tester

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/benvon/http-request-reliability-tester/internal/client"
	"github.com/benvon/http-request-reliability-tester/internal/config"
)

// ErrorType is an alias for client.ErrorType
type ErrorType = client.ErrorType

// TestResult represents the overall test results
type TestResult struct {
	TotalRequests     int
	TotalErrors       int
	ErrorBreakdown    map[ErrorType]int
	EndpointResults   map[string]*EndpointResult
	StartTime         time.Time
	EndTime           time.Time
	Duration          time.Duration
	RequestsPerMinute int
}

// EndpointResult represents results for a specific endpoint
type EndpointResult struct {
	Endpoint          string
	TotalRequests     int
	TotalErrors       int
	ErrorBreakdown    map[ErrorType]int
	SuccessCount      int
	AverageDuration   time.Duration
	LastError         error
	RecentStatusCodes []int
	Removed           bool
}

const recentStatusWindow = 3

// Tester represents the HTTP request reliability tester
type Tester struct {
	config        *config.Config
	client        *client.Client
	results       *TestResult
	mu            sync.RWMutex
	lastHeartbeat time.Time
}

// New creates a new tester instance
func New(cfg *config.Config) *Tester {
	client := client.New(30*time.Second, cfg.Debug)

	return &Tester{
		config: cfg,
		client: client,
		results: &TestResult{
			ErrorBreakdown:    make(map[ErrorType]int),
			EndpointResults:   make(map[string]*EndpointResult),
			StartTime:         time.Now(),
			RequestsPerMinute: cfg.RequestsPerMinute,
		},
		lastHeartbeat: time.Now(),
	}
}

// Run executes the HTTP request reliability test
func (t *Tester) Run(ctx context.Context) (*TestResult, error) {
	// Initialize endpoint results
	for _, endpoint := range t.config.Endpoints {
		t.results.EndpointResults[endpoint] = &EndpointResult{
			Endpoint:       endpoint,
			ErrorBreakdown: make(map[ErrorType]int),
		}
	}

	// Calculate request interval
	interval := time.Duration(60) * time.Second / time.Duration(t.config.RequestsPerMinute)

	// Determine test duration
	var testDuration time.Duration
	if t.config.Continuous {
		testDuration = 0 // Run until interrupted
	} else if t.config.RequestCount > 0 {
		testDuration = time.Duration(t.config.RequestCount) * interval
	} else {
		testDuration = t.config.Duration
	}

	// Create ticker for rate limiting
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Create context with timeout if not continuous
	if !t.config.Continuous && testDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, testDuration)
		defer cancel()
	}

	// Set up heartbeat ticker
	heartbeatTicker := time.NewTicker(10 * time.Second)
	defer heartbeatTicker.Stop()

	log.Printf("Starting HTTP reliability test with %d requests per minute", t.config.RequestsPerMinute)
	log.Printf("Test duration: %v", testDuration)
	log.Printf("Testing %d endpoints", len(t.config.Endpoints))

	requestCount := 0
	activeEndpoints := make([]string, len(t.config.Endpoints))
	copy(activeEndpoints, t.config.Endpoints)

	for {
		select {
		case <-ctx.Done():
			t.results.EndTime = time.Now()
			t.results.Duration = t.results.EndTime.Sub(t.results.StartTime)
			log.Printf("Test completed: %d requests, %d errors", t.results.TotalRequests, t.results.TotalErrors)
			return t.results, nil

		case <-heartbeatTicker.C:
			t.printHeartbeat()

		case <-ticker.C:
			// Skip if we've reached the request count limit
			if t.config.RequestCount > 0 && requestCount >= t.config.RequestCount {
				t.results.EndTime = time.Now()
				t.results.Duration = t.results.EndTime.Sub(t.results.StartTime)
				return t.results, nil
			}

			// Select random endpoint from active endpoints
			if len(activeEndpoints) == 0 {
				return t.results, fmt.Errorf("no active endpoints remaining")
			}

			// Use crypto/rand for secure random number generation
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(activeEndpoints))))
			if err != nil {
				return t.results, fmt.Errorf("failed to generate random number: %w", err)
			}
			endpointIndex := int(n.Int64())
			endpoint := activeEndpoints[endpointIndex]

			// Make request
			result := t.client.MakeRequest(ctx, endpoint)
			t.processResult(result)

			// Check if endpoint should be removed
			if t.shouldRemoveEndpoint(endpoint) {
				// Remove endpoint from active list
				activeEndpoints = append(activeEndpoints[:endpointIndex], activeEndpoints[endpointIndex+1:]...)
				t.results.EndpointResults[endpoint].Removed = true
			}

			requestCount++
		}
	}
}

// processResult processes a single request result
func (t *Tester) processResult(result *client.RequestResult) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Update overall results
	t.results.TotalRequests++
	if result.Error != nil {
		t.results.TotalErrors++
		t.results.ErrorBreakdown[result.ErrorType]++
	}

	// Update endpoint-specific results
	endpointResult := t.results.EndpointResults[result.Endpoint]
	endpointResult.TotalRequests++
	if endpointResult.TotalRequests > 0 {
		endpointResult.AverageDuration = (endpointResult.AverageDuration*time.Duration(endpointResult.TotalRequests-1) + result.Duration) / time.Duration(endpointResult.TotalRequests)
	}

	if result.Error == nil || result.ErrorType == client.ErrorTypeHTTP {
		endpointResult.RecentStatusCodes = append(endpointResult.RecentStatusCodes, result.StatusCode)
		if len(endpointResult.RecentStatusCodes) > recentStatusWindow {
			endpointResult.RecentStatusCodes = endpointResult.RecentStatusCodes[len(endpointResult.RecentStatusCodes)-recentStatusWindow:]
		}
	}

	if result.Error != nil {
		endpointResult.TotalErrors++
		endpointResult.ErrorBreakdown[result.ErrorType]++
		endpointResult.LastError = result.Error
	} else {
		endpointResult.SuccessCount++
	}
}

// shouldRemoveEndpoint determines if an endpoint should be removed from the test pool
func (t *Tester) shouldRemoveEndpoint(endpoint string) bool {
	endpointResult := t.results.EndpointResults[endpoint]

	if len(endpointResult.RecentStatusCodes) < recentStatusWindow {
		return false
	}

	for _, status := range endpointResult.RecentStatusCodes {
		if status > 0 && status < 400 {
			return false
		}
	}

	return true
}

// GetResults returns a copy of the current test results
func (t *Tester) GetResults() *TestResult {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Create a deep copy of results
	results := &TestResult{
		TotalRequests:     t.results.TotalRequests,
		TotalErrors:       t.results.TotalErrors,
		ErrorBreakdown:    make(map[ErrorType]int),
		EndpointResults:   make(map[string]*EndpointResult),
		StartTime:         t.results.StartTime,
		EndTime:           t.results.EndTime,
		Duration:          t.results.Duration,
		RequestsPerMinute: t.results.RequestsPerMinute,
	}

	// Copy error breakdown
	for errorType, count := range t.results.ErrorBreakdown {
		results.ErrorBreakdown[errorType] = count
	}

	// Copy endpoint results
	for endpoint, endpointResult := range t.results.EndpointResults {
		results.EndpointResults[endpoint] = &EndpointResult{
			Endpoint:          endpointResult.Endpoint,
			TotalRequests:     endpointResult.TotalRequests,
			TotalErrors:       endpointResult.TotalErrors,
			ErrorBreakdown:    make(map[ErrorType]int),
			SuccessCount:      endpointResult.SuccessCount,
			AverageDuration:   endpointResult.AverageDuration,
			LastError:         endpointResult.LastError,
			RecentStatusCodes: append([]int(nil), endpointResult.RecentStatusCodes...),
			Removed:           endpointResult.Removed,
		}

		for errorType, count := range endpointResult.ErrorBreakdown {
			results.EndpointResults[endpoint].ErrorBreakdown[errorType] = count
		}
	}

	return results
}

// printHeartbeat prints a heartbeat message with current progress
func (t *Tester) printHeartbeat() {
	t.mu.RLock()
	defer t.mu.RUnlock()

	elapsed := time.Since(t.results.StartTime)
	successRate := 0.0
	if t.results.TotalRequests > 0 {
		successRate = float64(t.results.TotalRequests-t.results.TotalErrors) / float64(t.results.TotalRequests) * 100
	}

	log.Printf("Heartbeat: %d requests, %d errors (%.1f%% success rate), %v elapsed",
		t.results.TotalRequests, t.results.TotalErrors, successRate, elapsed)
}
