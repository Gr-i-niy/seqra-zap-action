# Seqra + ZAP Security Scan Action

GitHub Action that combines Seqra SAST analysis with ZAP dynamic testing to identify and confirm security
vulnerabilities.

## Quick Start

```yaml
name: Security Scan
on: pull_request

permissions:
  contents: read
  security-events: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up JDK
        uses: actions/setup-java@v5
        with:
          distribution: 'temurin'
          java-version: '21'

      - name: Build project
        run: ./gradlew build

      - name: Start application
        run: |
          ./gradlew bootRun > app.log 2>&1 &
          echo $! > app.pid

          # Wait for app to be ready
          for i in {1..30}; do
            if curl -s http://localhost:8080/actuator/health > /dev/null; then
              echo "Application ready"
              break
            fi
            sleep 2
          done

      - name: Run security scan
        uses: your-org/seqra-zap-action@v1
        with:
          mode: 'differential'
          target: 'http://localhost:8080'
```

## Inputs

### Required

`target` - Target URL for ZAP dynamic scan (must be a running application)

### Optional

`mode` - Scan mode: `full` (scans current branch) or `differential` (compares PR against base branch). Default: `full`

`template` - Path to ZAP automation template. Default: `template.yaml`

`context-name` - Context name from template to use. Default: first context

`artifact-name` - Name of uploaded artifact. Default: `seqra-zap-scan-results`

`upload-sarif` - Upload confirmed findings to GitHub Code Security. Default: `true`

### Seqra Options

`project-root` - Project root path. Default: `.`

`seqra-version` - Seqra release tag. Default: `v2.4.0`

`rules-path` - Custom rules directories (comma-separated)

`seqra-timeout` - Scan timeout. Default: `15m`

### ZAP Options

`zap-docker-image` - ZAP Docker image. Default: `ghcr.io/zaproxy/zaproxy:stable`

`zap-docker-env-vars` - Environment variables for ZAP container

`zap-cmd-options` - Additional ZAP command line options

## Template

The action uses a [ZAP automation framework](https://www.zaproxy.org/docs/desktop/addons/automation-framework/) YAML
file.

### Requirements

1. At least one context in `env.contexts`
2. API import job (`openapi` or `graphql`)
3. At least one CWE policy with format `policy-CWE-{number}`

### Details

The action automatically:

- Adds required JSON report if missing
- Normalizes all report directories to `/zap/wrk/zap-output`
- Generates CWE-specific contexts based on Seqra findings
- Creates activeScan jobs for matching CWEs

Policy naming: Use `policy-CWE-{number}` format (e.g., `policy-CWE-89` for SQL Injection, `policy-CWE-79` for XSS).

### Example

```yaml
env:
  contexts:
    - name: default-context
      urls:
        - http://localhost:8080

jobs:
  - type: openapi
    parameters:
      context: default-context
      targetUrl: http://localhost:8080
      apiUrl: http://localhost:8080/v3/api-docs

  - type: activeScan-config
    parameters:
      threadPerHost: 40

  - type: activeScan-policy
    parameters:
      name: policy-CWE-89
    policyDefinition:
      defaultStrength: INSANE
      defaultThreshold: 'OFF'
      rules:
        - id: 40018
          threshold: MEDIUM
```

See [template.yaml](template.yaml) for a complete example.

## Artifacts

The action uploads an artifact with:

`filtered-confirmed.sarif` - sarif with ZAP-confirmed vulnerabilities

ZAP reports from `/zap/wrk/zap-output` folder

Sarif from Seqra scan based on mode:

`full`: `seqra-scan.sarif` (all Seqra findings)

`differential`: `filtered-seqra.sarif` (new findings only)

## Examples

[example.yml](.github/workflows/example.yml) - Differential scan for pull requests

[example-full-scan.yml](.github/workflows/example-full-scan.yml) - Full scan for main branch

## Requirements

- Application must be running and accessible at target URL
- Java/Kotlin projects with Spring framework
- OpenAPI or GraphQL scheme for API import
