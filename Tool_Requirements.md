# HTTP REQUEST RELIABILITY TESTER

## Overview

The goal of this tool is to run multiple HTTP request streams over a given period of time and record the reliability of those HTTP requests. The errors that the tool is meant to uncover is on the local system and the infrastructure (proxies, caches, etc) between the local requesting system and the far-side endpoint. The tool is not (necessarily) meant to test the far-side endpoint. The tool is meant to find and report on issues on the connection setup before the HTTP request is transmitted to the far-side endpoint.

## Requirements

This tool will:

* be a well-formed, best-practices compliant Go command line utility.
* be configurable via environment variables, command-line options, or configuration file with the precedence for configuration being in that order with the environment variables being the most precedent and the configuration file being least.
* have these configurable options
  * request endpoints as a list
  * a duration for the test to run
    * Can be defined in the total number of requests to send or in minutes
  * the ability to run continuously until a break (control-c) is received
  * the rate at which to send requests (measured in requests per minute)
  * a special flag must be passed if the requests per minute for any single endpoint will exceed 60
  * a "debug" option that will output extended error details when the http request fails
  * output options to include, json, csv, and markdown table
  * markdown table will be the default output method.
* When stopped via the control-c, the tool should output the results to the configured output method
* The output of the tool will include (at least) this data
  * total number of requests sent
  * total number of errors
  * the number of errors broken down by the type of error
* The tool should emulate as closely as possible the operations of the Chrome web browser when making requests, including but not limited to:
  * DNS query
  * TLS setup and teardown
  * preflight requests
  * HTTP OPTION requests
* By default, the tool should use these public HTTP endpoints for testing:
  * httpbin: https://httpbin.org
  * postman echo: https://postman-echo.com
  * mocky.io: https://run.mocky.io
  * JSONPlaceholder: https://jsonplaceholder.typicode.com
  * httpbingo: https://httpbingo.org
  * beeceptor: https://beeceptor.com
  * requestbin: https://requestbin.com
  * webhook.site: https://webhook.site
  * hookbin: https://hookbin.com
  * httpstat.us: https://httpstat.us
  * mocki.io: https://mocki.io
* If any site in the test pool responds with an error code (>=400) more than two times it should be removed from the test pool.
* Unit tests will be created to test all the internal logic.
  * Code coverage should meet at least 70% lines of code.
  * Tests should not test external services.
* The tool should provide some "heartbeat" output at least every 10 seconds.
* If the tool encounters an error, it should immediately output a structured error message that contains useful information for understanding the nature of the error.

In addition:

* A Github workflow will be created using `goreleaser` to create releases.
  * A release will be based on a semver tag being pushed to the repo.
  * The semver tag will support the extended format such as `1.2.3-rc1`
* A Github workflow will be created to run tests on PR to the main branch.
  * tests should include the unit test, but also gosec, golangci-lint, and other common go quality control tests.
* A dependabot configuration will be created to maintain the github workflows and the go modules.
* A Makefile will be created that will have targets for building and testing on the local developer system.
* Any required tools for local development will be installed using `asdf` with versions maintained in `.tool-versions`
