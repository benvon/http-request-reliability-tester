# HTTP Request Reliability Tester

A Go command-line utility for testing HTTP request reliability across multiple endpoints. This tool emulates Chrome browser behavior and helps identify connection issues in your local infrastructure and network path.

## Features

- **Chrome-like behavior**: Emulates DNS queries, TLS setup/teardown, preflight requests, and HTTP OPTIONS
- **Multiple output formats**: Markdown (default), JSON, and CSV
- **Configurable endpoints**: Test against custom endpoints or use built-in public endpoints
- **Rate limiting**: Control requests per minute with safety limits
- **Error classification**: Detailed breakdown of DNS, TLS, connection, timeout, and HTTP errors
- **Endpoint management**: Automatically removes endpoints with consistent HTTP errors
- **Graceful shutdown**: Handles Ctrl+C interruption with result output

## Installation

### From Source

```bash
git clone https://github.com/benvon/http-request-reliability-tester.git
cd http-request-reliability-tester
make build
```

### Using Go

```bash
go install github.com/benvon/http-request-reliability-tester@latest
```

## Usage

### Basic Usage

```bash
# Run with default settings (5 minutes, 60 requests/minute)
./http-tester

# Run for 1 minute
./http-tester --duration 1m

# Run 100 requests
./http-tester --count 100

# Run continuously until interrupted
./http-tester --continuous
```

### Advanced Usage

```bash
# Custom endpoints
./http-tester --endpoints "https://api.example.com,https://api2.example.com"

# Higher rate (requires --high-rate flag)
./http-tester --rate 120 --high-rate

# Custom output format
./http-tester --output json --output-file results.json

# Environment variables
export HTTP_TESTER_ENDPOINTS="https://api.example.com"
export HTTP_TESTER_DURATION="10m"
export HTTP_TESTER_RATE="30"
./http-tester
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--endpoints` | Comma-separated list of endpoints | Built-in public endpoints |
| `--duration` | Test duration (e.g., "5m", "30s") | 5 minutes |
| `--count` | Total number of requests to send | 0 (duration-based) |
| `--continuous` | Run continuously until interrupted | false |
| `--rate` | Requests per minute | 60 |
| `--high-rate` | Allow rates exceeding 60 requests/minute | false |
| `--output` | Output format: markdown, json, csv | markdown |
| `--output-file` | Output file path (default: stdout) | "" |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `HTTP_TESTER_ENDPOINTS` | Comma-separated list of endpoints |
| `HTTP_TESTER_DURATION` | Test duration |
| `HTTP_TESTER_COUNT` | Total number of requests |
| `HTTP_TESTER_CONTINUOUS` | Run continuously (true/false) |
| `HTTP_TESTER_RATE` | Requests per minute |
| `HTTP_TESTER_HIGH_RATE` | Allow high rates (true/false) |
| `HTTP_TESTER_OUTPUT` | Output format |
| `HTTP_TESTER_OUTPUT_FILE` | Output file path |

## Default Endpoints

The tool includes these public HTTP endpoints for testing:

- https://httpbin.org
- https://postman-echo.com
- https://run.mocky.io
- https://jsonplaceholder.typicode.com
- https://httpbingo.org
- https://beeceptor.com
- https://requestbin.com
- https://webhook.site
- https://hookbin.com
- https://httpstat.us
- https://mocki.io

## Output Formats

### Markdown (Default)

```markdown
# HTTP Request Reliability Test Results

**Test Duration:** 5m0s
**Start Time:** 2024-01-15T10:00:00Z
**End Time:** 2024-01-15T10:05:00Z
**Requests Per Minute:** 60

## Overall Statistics

- **Total Requests:** 300
- **Total Errors:** 5
- **Success Rate:** 98.33%

## Error Breakdown

| Error Type | Count | Percentage |
|------------|-------|------------|
| timeout | 3 | 60.00% |
| connection | 2 | 40.00% |

## Endpoint Results

| Endpoint | Requests | Errors | Success Rate | Avg Duration | Status |
|----------|----------|--------|--------------|--------------|--------|
| https://httpbin.org | 100 | 0 | 100.00% | 150ms | Active |
| https://postman-echo.com | 100 | 2 | 98.00% | 200ms | Active |
```

### JSON

```json
{
  "summary": {
    "total_requests": 300,
    "total_errors": 5,
    "success_rate": 98.33,
    "duration": "5m0s",
    "requests_per_minute": 60,
    "start_time": "2024-01-15T10:00:00Z",
    "end_time": "2024-01-15T10:05:00Z"
  },
  "error_breakdown": {
    "timeout": 3,
    "connection": 2
  },
  "endpoints": {
    "https://httpbin.org": {
      "requests": 100,
      "errors": 0,
      "success_rate": 100.0,
      "avg_duration": "150ms",
      "removed": false
    }
  }
}
```

### CSV

```csv
Summary
Total Requests,300
Total Errors,5
Success Rate,98.33%
Duration,5m0s
Requests Per Minute,60

Error Breakdown
Error Type,Count,Percentage
timeout,3,60.00%
connection,2,40.00%

Endpoint Results
Endpoint,Requests,Errors,Success Rate,Avg Duration,Status
https://httpbin.org,100,0,100.00%,150ms,Active
```

## Development

### Prerequisites

- Go 1.24 or later
- Make (optional, for using Makefile)

### Building

```bash
# Build the application
make build

# Or directly with go
go build -o http-tester .
```

### Testing

```bash
# Run all tests
make test

# Run tests with coverage
make coverage

# Run tests with race detection
go test -race ./...
```

### Linting

```bash
# Install golangci-lint
make install-tools

# Run linter
make lint
```

## Docker

### Build and Run

```bash
# Build the Docker image
docker build -t http-tester .

# Run with default settings
docker run http-tester

# Run with custom settings
docker run http-tester --duration 1m --rate 30
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with Go
- Uses public HTTP endpoints for testing
- Emulates Chrome browser behavior for realistic testing
