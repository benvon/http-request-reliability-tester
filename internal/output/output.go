package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/benvon/http-request-reliability-tester/internal/client"
	"github.com/benvon/http-request-reliability-tester/internal/config"
	"github.com/benvon/http-request-reliability-tester/internal/tester"
)

// Write writes test results in the specified format
func Write(results *tester.TestResult, format config.OutputFormat, outputFile string) error {
	var output string
	var err error

	switch format {
	case config.OutputFormatMarkdown:
		output, err = formatMarkdown(results)
	case config.OutputFormatJSON:
		output, err = formatJSON(results)
	case config.OutputFormatCSV:
		output, err = formatCSV(results)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	// Write to file or stdout
	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(output), 0600); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
	} else {
		fmt.Print(output)
	}

	return nil
}

// formatMarkdown formats results as a markdown table
func formatMarkdown(results *tester.TestResult) (string, error) {
	var sb strings.Builder

	// Summary section
	sb.WriteString("# HTTP Request Reliability Test Results\n\n")
	sb.WriteString(fmt.Sprintf("**Test Duration:** %s\n", results.Duration))
	sb.WriteString(fmt.Sprintf("**Start Time:** %s\n", results.StartTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**End Time:** %s\n", results.EndTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Requests Per Minute:** %d\n\n", results.RequestsPerMinute))

	// Overall statistics
	sb.WriteString("## Overall Statistics\n\n")
	sb.WriteString(fmt.Sprintf("- **Total Requests:** %d\n", results.TotalRequests))
	sb.WriteString(fmt.Sprintf("- **Total Errors:** %d\n", results.TotalErrors))
	// Calculate success rate safely
	var successRate float64
	if results.TotalRequests > 0 {
		successRate = float64(results.TotalRequests-results.TotalErrors) / float64(results.TotalRequests) * 100
	} else {
		successRate = 0
	}
	sb.WriteString(fmt.Sprintf("- **Success Rate:** %.2f%%\n\n", successRate))

	// Error breakdown
	if results.TotalErrors > 0 {
		sb.WriteString("## Error Breakdown\n\n")
		sb.WriteString("| Error Type | Count | Percentage |\n")
		sb.WriteString("|------------|-------|------------|\n")

		for errorType, count := range results.ErrorBreakdown {
			percentage := float64(count) / float64(results.TotalErrors) * 100
			sb.WriteString(fmt.Sprintf("| %s | %d | %.2f%% |\n", errorType, count, percentage))
		}
		sb.WriteString("\n")
	}

	// Endpoint results
	sb.WriteString("## Endpoint Results\n\n")
	sb.WriteString("| Endpoint | Requests | Errors | Success Rate | Avg Duration | Status |\n")
	sb.WriteString("|----------|----------|--------|--------------|--------------|--------|\n")

	for _, endpointResult := range results.EndpointResults {
		// Calculate success rate safely
		var successRate float64
		if endpointResult.TotalRequests > 0 {
			successRate = float64(endpointResult.SuccessCount) / float64(endpointResult.TotalRequests) * 100
		} else {
			successRate = 0
		}

		status := "Active"
		if endpointResult.Removed {
			status = "Removed"
		}

		sb.WriteString(fmt.Sprintf("| %s | %d | %d | %.2f%% | %s | %s |\n",
			endpointResult.Endpoint,
			endpointResult.TotalRequests,
			endpointResult.TotalErrors,
			successRate,
			endpointResult.AverageDuration,
			status))
	}

	return sb.String(), nil
}

// formatJSON formats results as JSON
func formatJSON(results *tester.TestResult) (string, error) {
	// Create a simplified structure for JSON output
	jsonResult := struct {
		Summary struct {
			TotalRequests     int           `json:"total_requests"`
			TotalErrors       int           `json:"total_errors"`
			SuccessRate       float64       `json:"success_rate"`
			Duration          time.Duration `json:"duration"`
			RequestsPerMinute int           `json:"requests_per_minute"`
			StartTime         time.Time     `json:"start_time"`
			EndTime           time.Time     `json:"end_time"`
		} `json:"summary"`
		ErrorBreakdown map[client.ErrorType]int `json:"error_breakdown"`
		Endpoints      map[string]struct {
			Requests    int           `json:"requests"`
			Errors      int           `json:"errors"`
			SuccessRate float64       `json:"success_rate"`
			AvgDuration time.Duration `json:"avg_duration"`
			Removed     bool          `json:"removed"`
		} `json:"endpoints"`
	}{}

	// Fill summary
	jsonResult.Summary.TotalRequests = results.TotalRequests
	jsonResult.Summary.TotalErrors = results.TotalErrors

	// Calculate success rate safely
	if results.TotalRequests > 0 {
		jsonResult.Summary.SuccessRate = float64(results.TotalRequests-results.TotalErrors) / float64(results.TotalRequests) * 100
	} else {
		jsonResult.Summary.SuccessRate = 0
	}

	jsonResult.Summary.Duration = results.Duration
	jsonResult.Summary.RequestsPerMinute = results.RequestsPerMinute
	jsonResult.Summary.StartTime = results.StartTime
	jsonResult.Summary.EndTime = results.EndTime

	// Fill error breakdown
	jsonResult.ErrorBreakdown = results.ErrorBreakdown

	// Fill endpoints
	jsonResult.Endpoints = make(map[string]struct {
		Requests    int           `json:"requests"`
		Errors      int           `json:"errors"`
		SuccessRate float64       `json:"success_rate"`
		AvgDuration time.Duration `json:"avg_duration"`
		Removed     bool          `json:"removed"`
	})

	for endpoint, result := range results.EndpointResults {
		// Calculate success rate safely
		var successRate float64
		if result.TotalRequests > 0 {
			successRate = float64(result.SuccessCount) / float64(result.TotalRequests) * 100
		} else {
			successRate = 0
		}

		jsonResult.Endpoints[endpoint] = struct {
			Requests    int           `json:"requests"`
			Errors      int           `json:"errors"`
			SuccessRate float64       `json:"success_rate"`
			AvgDuration time.Duration `json:"avg_duration"`
			Removed     bool          `json:"removed"`
		}{
			Requests:    result.TotalRequests,
			Errors:      result.TotalErrors,
			SuccessRate: successRate,
			AvgDuration: result.AverageDuration,
			Removed:     result.Removed,
		}
	}

	jsonBytes, err := json.MarshalIndent(jsonResult, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(jsonBytes), nil
}

// formatCSV formats results as CSV
func formatCSV(results *tester.TestResult) (string, error) {
	var sb strings.Builder
	writer := csv.NewWriter(&sb)

	// Write summary
	if err := writer.Write([]string{"Summary"}); err != nil {
		return "", fmt.Errorf("failed to write CSV: %w", err)
	}
	if err := writer.Write([]string{"Total Requests", fmt.Sprintf("%d", results.TotalRequests)}); err != nil {
		return "", fmt.Errorf("failed to write CSV: %w", err)
	}
	if err := writer.Write([]string{"Total Errors", fmt.Sprintf("%d", results.TotalErrors)}); err != nil {
		return "", fmt.Errorf("failed to write CSV: %w", err)
	}
	if err := writer.Write([]string{"Success Rate", fmt.Sprintf("%.2f%%",
		float64(results.TotalRequests-results.TotalErrors)/float64(results.TotalRequests)*100)}); err != nil {
		return "", fmt.Errorf("failed to write CSV: %w", err)
	}
	if err := writer.Write([]string{"Duration", results.Duration.String()}); err != nil {
		return "", fmt.Errorf("failed to write CSV: %w", err)
	}
	if err := writer.Write([]string{"Requests Per Minute", fmt.Sprintf("%d", results.RequestsPerMinute)}); err != nil {
		return "", fmt.Errorf("failed to write CSV: %w", err)
	}
	if err := writer.Write([]string{}); err != nil { // Empty row
		return "", fmt.Errorf("failed to write CSV: %w", err)
	}

	// Write error breakdown
	if len(results.ErrorBreakdown) > 0 {
		if err := writer.Write([]string{"Error Breakdown"}); err != nil {
			return "", fmt.Errorf("failed to write CSV: %w", err)
		}
		if err := writer.Write([]string{"Error Type", "Count", "Percentage"}); err != nil {
			return "", fmt.Errorf("failed to write CSV: %w", err)
		}

		for errorType, count := range results.ErrorBreakdown {
			percentage := float64(count) / float64(results.TotalErrors) * 100
			if err := writer.Write([]string{string(errorType), fmt.Sprintf("%d", count), fmt.Sprintf("%.2f%%", percentage)}); err != nil {
				return "", fmt.Errorf("failed to write CSV: %w", err)
			}
		}
		if err := writer.Write([]string{}); err != nil { // Empty row
			return "", fmt.Errorf("failed to write CSV: %w", err)
		}
	}

	// Write endpoint results
	if err := writer.Write([]string{"Endpoint Results"}); err != nil {
		return "", fmt.Errorf("failed to write CSV: %w", err)
	}
	if err := writer.Write([]string{"Endpoint", "Requests", "Errors", "Success Rate", "Avg Duration", "Status"}); err != nil {
		return "", fmt.Errorf("failed to write CSV: %w", err)
	}

	for _, endpointResult := range results.EndpointResults {
		// Calculate success rate safely
		var successRate float64
		if endpointResult.TotalRequests > 0 {
			successRate = float64(endpointResult.SuccessCount) / float64(endpointResult.TotalRequests) * 100
		} else {
			successRate = 0
		}

		status := "Active"
		if endpointResult.Removed {
			status = "Removed"
		}

		if err := writer.Write([]string{
			endpointResult.Endpoint,
			fmt.Sprintf("%d", endpointResult.TotalRequests),
			fmt.Sprintf("%d", endpointResult.TotalErrors),
			fmt.Sprintf("%.2f%%", successRate),
			endpointResult.AverageDuration.String(),
			status,
		}); err != nil {
			return "", fmt.Errorf("failed to write CSV: %w", err)
		}
	}

	writer.Flush()
	return sb.String(), writer.Error()
}
