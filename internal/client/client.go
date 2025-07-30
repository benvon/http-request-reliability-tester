package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrorType represents different types of errors that can occur
type ErrorType string

const (
	ErrorTypeDNS        ErrorType = "dns"
	ErrorTypeTLS        ErrorType = "tls"
	ErrorTypeConnection ErrorType = "connection"
	ErrorTypeTimeout    ErrorType = "timeout"
	ErrorTypeHTTP       ErrorType = "http"
	ErrorTypeOther      ErrorType = "other"
)

// RequestResult represents the result of a single HTTP request
type RequestResult struct {
	Endpoint    string
	StatusCode  int
	Error       error
	ErrorType   ErrorType
	Duration    time.Duration
	Timestamp   time.Time
	DNSDuration time.Duration
	TLSDuration time.Duration
}

// Client represents an HTTP client that emulates Chrome browser behavior
type Client struct {
	httpClient *http.Client
	timeout    time.Duration
	debug      bool
}

// New creates a new HTTP client with Chrome-like behavior
func New(timeout time.Duration, debug bool) *Client {
	// Create transport with Chrome-like settings
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	return &Client{
		httpClient: client,
		timeout:    timeout,
		debug:      debug,
	}
}

// MakeRequest performs a single HTTP request with Chrome-like behavior
func (c *Client) MakeRequest(ctx context.Context, endpoint string) *RequestResult {
	result := &RequestResult{
		Endpoint:  endpoint,
		Timestamp: time.Now(),
	}

	start := time.Now()

	// Parse URL
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		result.Error = fmt.Errorf("url parse error: invalid URL '%s' - %w", endpoint, err)
		result.ErrorType = ErrorTypeOther
		result.Duration = time.Since(start)
		c.printDebugInfo(result)
		return result
	}

	// DNS resolution timing
	dnsStart := time.Now()
	_, err = net.LookupHost(parsedURL.Hostname())
	dnsDuration := time.Since(dnsStart)
	result.DNSDuration = dnsDuration

	if err != nil {
		result.Error = fmt.Errorf("dns error: lookup failed for '%s' - %w", parsedURL.Hostname(), err)
		result.ErrorType = ErrorTypeDNS
		result.Duration = time.Since(start)
		c.printDebugInfo(result)
		return result
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		result.Error = fmt.Errorf("request creation error: failed to create HTTP request for '%s' - %w", endpoint, err)
		result.ErrorType = ErrorTypeOther
		result.Duration = time.Since(start)
		c.printDebugInfo(result)
		return result
	}

	// Add Chrome-like headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Cache-Control", "max-age=0")

	// For HTTPS endpoints, perform preflight OPTIONS request
	if parsedURL.Scheme == "https" {
		preflightResult := c.performPreflight(ctx, endpoint)
		if preflightResult.Error != nil {
			result.Error = fmt.Errorf("preflight error: HTTPS preflight request failed for '%s' - %w", endpoint, preflightResult.Error)
			result.ErrorType = preflightResult.ErrorType
			result.Duration = time.Since(start)
			c.printDebugInfo(result)
			return result
		}
		result.TLSDuration = preflightResult.TLSDuration
	}

	// Perform the actual request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("http request error: failed to execute request to '%s' - %w", endpoint, err)
		result.ErrorType = c.classifyError(err)
		result.Duration = time.Since(start)
		c.printDebugInfo(result)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Duration = time.Since(start)

	// Check for HTTP error status codes
	if resp.StatusCode >= 400 {
		result.Error = fmt.Errorf("http status error: received status %d (%s) from '%s'", resp.StatusCode, resp.Status, endpoint)
		result.ErrorType = ErrorTypeHTTP
		c.printDebugInfo(result)
	}

	return result
}

// performPreflight performs a preflight OPTIONS request for CORS
func (c *Client) performPreflight(ctx context.Context, endpoint string) *RequestResult {
	result := &RequestResult{
		Endpoint:  endpoint,
		Timestamp: time.Now(),
	}

	start := time.Now()

	// Create OPTIONS request
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", endpoint, nil)
	if err != nil {
		result.Error = fmt.Errorf("preflight creation error: failed to create OPTIONS request for '%s' - %w", endpoint, err)
		result.ErrorType = ErrorTypeOther
		result.Duration = time.Since(start)
		return result
	}

	// Add CORS preflight headers
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "content-type")

	// Perform preflight request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		result.Error = err
		result.ErrorType = c.classifyError(err)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Duration = time.Since(start)

	// Note: We don't fail on preflight errors as some servers don't support CORS
	// but still work fine for regular requests

	return result
}

// classifyError classifies the error type based on the error message
func (c *Client) classifyError(err error) ErrorType {
	errStr := err.Error()

	switch {
	case strings.Contains(errStr, "no such host"):
		return ErrorTypeDNS
	case strings.Contains(errStr, "tls"):
		return ErrorTypeTLS
	case strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "network is unreachable"):
		return ErrorTypeConnection
	case strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "deadline exceeded"):
		return ErrorTypeTimeout
	case strings.Contains(errStr, "http"):
		return ErrorTypeHTTP
	default:
		return ErrorTypeOther
	}
}

// printDebugInfo prints detailed debug information for failed requests
func (c *Client) printDebugInfo(result *RequestResult) {
	if !c.debug || result.Error == nil {
		return
	}

	fmt.Printf("\n[DEBUG] Request failed for %s:\n", result.Endpoint)
	fmt.Printf("  Error Type: %s\n", result.ErrorType)
	fmt.Printf("  Error Message: %s\n", result.Error.Error())
	fmt.Printf("  Duration: %v\n", result.Duration)
	fmt.Printf("  DNS Duration: %v\n", result.DNSDuration)
	if result.TLSDuration > 0 {
		fmt.Printf("  TLS Duration: %v\n", result.TLSDuration)
	}
	if result.StatusCode > 0 {
		fmt.Printf("  Status Code: %d\n", result.StatusCode)
	}
	fmt.Printf("  Timestamp: %s\n", result.Timestamp.Format("2006-01-02 15:04:05.000"))
	fmt.Println()
}
