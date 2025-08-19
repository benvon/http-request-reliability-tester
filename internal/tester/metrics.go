package tester

// OverallSuccessRate calculates the overall success rate as a percentage.
func OverallSuccessRate(result *TestResult) float64 {
	if result == nil || result.TotalRequests == 0 {
		return 0
	}
	return float64(result.TotalRequests-result.TotalErrors) / float64(result.TotalRequests) * 100
}

// EndpointSuccessRate calculates the success rate for a single endpoint as a percentage.
func EndpointSuccessRate(result *EndpointResult) float64 {
	if result == nil || result.TotalRequests == 0 {
		return 0
	}
	return float64(result.SuccessCount) / float64(result.TotalRequests) * 100
}
