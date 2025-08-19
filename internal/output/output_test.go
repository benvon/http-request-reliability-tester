package output

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/benvon/http-request-reliability-tester/internal/client"
	"github.com/benvon/http-request-reliability-tester/internal/config"
	"github.com/benvon/http-request-reliability-tester/internal/tester"
)

func TestFormatMarkdown(t *testing.T) {
	results := createTestResults()

	output, err := formatMarkdown(results)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !strings.Contains(output, "# HTTP Request Reliability Test Results") {
		t.Error("Expected markdown header")
	}

	if !strings.Contains(output, "## Overall Statistics") {
		t.Error("Expected overall statistics section")
	}

	if !strings.Contains(output, "## Error Breakdown") {
		t.Error("Expected error breakdown section")
	}

	if !strings.Contains(output, "## Endpoint Results") {
		t.Error("Expected endpoint results section")
	}

	if !strings.Contains(output, "https://example.com") {
		t.Error("Expected endpoint in output")
	}
	expected := fmt.Sprintf("%.2f%%", tester.OverallSuccessRate(results))
	if strings.Count(output, expected) < 2 {
		t.Errorf("Expected success rate %s to appear twice", expected)
	}
}

func TestFormatJSON(t *testing.T) {
	results := createTestResults()

	output, err := formatJSON(results)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !strings.Contains(output, `"summary"`) {
		t.Error("Expected summary section in JSON")
	}

	if !strings.Contains(output, `"error_breakdown"`) {
		t.Error("Expected error breakdown in JSON")
	}

	if !strings.Contains(output, `"endpoints"`) {
		t.Error("Expected endpoints section in JSON")
	}

	if !strings.Contains(output, `"https://example.com"`) {
		t.Error("Expected endpoint in JSON output")
	}
	expected := strconv.FormatFloat(tester.OverallSuccessRate(results), 'f', -1, 64)
	if strings.Count(output, fmt.Sprintf("\"success_rate\": %s", expected)) < 2 {
		t.Errorf("Expected success rate %s to appear twice in JSON output", expected)
	}
}

func TestFormatCSV(t *testing.T) {
	results := createTestResults()

	output, err := formatCSV(results)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !strings.Contains(output, "Summary") {
		t.Error("Expected summary section in CSV")
	}

	if !strings.Contains(output, "Error Breakdown") {
		t.Error("Expected error breakdown section in CSV")
	}

	if !strings.Contains(output, "Endpoint Results") {
		t.Error("Expected endpoint results section in CSV")
	}

	if !strings.Contains(output, "https://example.com") {
		t.Error("Expected endpoint in CSV output")
	}
	expected := fmt.Sprintf("%.2f%%", tester.OverallSuccessRate(results))
	if strings.Count(output, expected) < 2 {
		t.Errorf("Expected success rate %s to appear twice in CSV output", expected)
	}
}

func TestWriteToFile(t *testing.T) {
	results := createTestResults()
	tempFile := "test_output.md"
	defer func() {
		_ = os.Remove(tempFile)
	}()

	err := Write(results, config.OutputFormatMarkdown, tempFile)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check if file was created
	if _, err := os.Stat(tempFile); os.IsNotExist(err) {
		t.Error("Expected output file to be created")
	}

	// Read file content
	content, err := os.ReadFile(tempFile)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	if !strings.Contains(string(content), "# HTTP Request Reliability Test Results") {
		t.Error("Expected markdown content in file")
	}
}

func TestWriteToStdout(t *testing.T) {
	results := createTestResults()

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	err := Write(results, config.OutputFormatMarkdown, "")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	_ = w.Close()
	output := make([]byte, 1024)
	n, _ := r.Read(output)

	if !strings.Contains(string(output[:n]), "# HTTP Request Reliability Test Results") {
		t.Error("Expected markdown content in stdout")
	}
}

func TestWriteInvalidFormat(t *testing.T) {
	results := createTestResults()

	err := Write(results, "invalid", "")
	if err == nil {
		t.Error("Expected error for invalid format")
	}

	if !strings.Contains(err.Error(), "unsupported output format") {
		t.Errorf("Expected specific error message, got %v", err)
	}
}

// createTestResults creates a test result for testing
func createTestResults() *tester.TestResult {
	results := &tester.TestResult{
		TotalRequests:     10,
		TotalErrors:       2,
		ErrorBreakdown:    make(map[client.ErrorType]int),
		EndpointResults:   make(map[string]*tester.EndpointResult),
		StartTime:         time.Now().Add(-5 * time.Minute),
		EndTime:           time.Now(),
		Duration:          5 * time.Minute,
		RequestsPerMinute: 60,
	}

	results.ErrorBreakdown[client.ErrorTypeConnection] = 1
	results.ErrorBreakdown[client.ErrorTypeTimeout] = 1

	results.EndpointResults["https://example.com"] = &tester.EndpointResult{
		Endpoint:          "https://example.com",
		TotalRequests:     10,
		TotalErrors:       2,
		SuccessCount:      8,
		AverageDuration:   100 * time.Millisecond,
		ErrorBreakdown:    make(map[client.ErrorType]int),
		RecentStatusCodes: []int{},
		Removed:           false,
	}

	results.EndpointResults["https://example.com"].ErrorBreakdown[client.ErrorTypeConnection] = 1
	results.EndpointResults["https://example.com"].ErrorBreakdown[client.ErrorTypeTimeout] = 1

	return results
}
