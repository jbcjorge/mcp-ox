# mcp-ox-security

A Go MCP server for OX Security that wraps the GraphQL API directly, filling the gaps left by the official OX MCP server.

## What this fixes

The official OX MCP server cannot:
- Look up a specific issue by ID
- Get an issue's relationship graph
- Filter issues by owner email using structured filters (it uses unreliable free-text search)
- Get resolved/removed issues by ID
- Get issue prioritization data
- List vulnerable libraries with CVE details
- Query pipeline issues

This server uses the OX GraphQL API's `conditionalFilters` for reliable, structured filtering.

## Tools

### Issue tools

| Tool | Description |
|------|-------------|
| `get_issue` | Get full details of a specific issue by ID |
| `get_issue_graph` | Get the relationship graph of an issue (nodes + edges) |
| `get_issue_prioritization` | Get prioritization score/factors for an issue |
| `get_resolved_issue` | Get details of a resolved issue by ID |
| `get_removed_issue` | Get details of a removed/disappeared issue by ID |
| `search_issues` | Search issues with structured filters (see below) |
| `get_issue_filters` | Get faceted breakdown of issues by category, severity, app, etc. |

### Application tools

| Tool | Description |
|------|-------------|
| `list_applications` | List all apps with security posture, risk scores, issue counts, owners |

### SBOM tools

| Tool | Description |
|------|-------------|
| `get_sbom` | List all dependencies for an app (versions, licenses, vuln counts) |
| `get_sbom_library_details` | Full details for one library, including its complete CVE list (drill-down from `get_sbom`) |
| `get_vulnerable_libraries` | List vulnerable deps with CVE details, EPSS, fix versions, exploit info |

### Pipeline tools

| Tool | Description |
|------|-------------|
| `get_pipeline_issues` | CI/CD pipeline findings with job details, enforcement, PR links |

### Write tools

These modify state in OX Security. Use with care.

| Tool | Description |
|------|-------------|
| `add_comment_to_issue` | Add a comment to an issue (investigation notes, audit trail) |
| `change_severity` | Override an issue's severity (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical, 5=Appox) |
| `report_false_positive` | Mark a regular (scan) issue as a false positive with a comment |
| `report_false_positive_pipeline` | Mark a CI/CD pipeline issue as a false positive with a comment |
| `exclude_issues` | Bulk-exclude one or more issues, with optional comment and expiry date |

## search_issues filters

All filters combine as AND conditions via `conditionalFilters`:

| Filter | Description | Example values |
|--------|-------------|----------------|
| `app_name` | Application name | `my-frontend-app` |
| `severity` | Severity level | `Critical`, `High`, `Medium`, `Low`, `Info` |
| `category` | Issue category | `Code Security`, `Open Source Security`, `SBOM`, `Secret/PII Scan` |
| `owner` | Owner email | `team@example.com` |
| `status` | Issue status | `open`, `resolved`, `removed` |
| `sla` | SLA status | `Within`, `Overdue` |
| `cve` | CVE identifier | `CVE-2024-1234` |
| `first_seen_after` | Issues first seen after date | `2024-07-01` (ISO 8601) |
| `first_seen_before` | Issues first seen before date | `2024-12-31` (ISO 8601) |
| `title` | Title text search (free-text) | `Untrusted` |

## get_issue_filters facets

Available facets for `get_issue_filters`:

`categories`, `criticality`, `apps`, `slaStatus`, `sourceTools`, `issueOwners`, `cve`, `languages`, `severityChangeReasons`, `appOwnersName`

## Setup

```bash
# Build
make build

# Or install globally
make install

# Cross-compile for distribution
make release
```

## Configuration

| Env var | Required | Default | Description |
|---------|----------|---------|-------------|
| `OX_API_TOKEN` | Yes | - | OX Security API token |
| `OX_API_URL` | No | `https://api.cloud.ox.security/api/apollo-gateway` | API endpoint (for on-prem) |
| `MCP_TRANSPORT` | No | `stdio` | Transport mode: `stdio`, `http`/`streamable-http`, or `sse` |
| `MCP_ADDR` | No | `:8080` | Listen address for HTTP/SSE modes |
| `LOG_LEVEL` | No | `info` | Log level: `debug`, `info`, `warn`, `error` |

## Usage

### Kiro agent config

Add to your `~/.kiro/agents/<name>.json`:

```json
{
  "mcpServers": {
    "ox-security-direct": {
      "command": "/path/to/mcp-ox-security",
      "env": {
        "OX_API_TOKEN": "your-token-here"
      }
    }
  }
}
```

### Behind mcp-gateway (HTTP mode)

```bash
MCP_TRANSPORT=http MCP_ADDR=:8080 OX_API_TOKEN=... ./mcp-ox-security
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ox-security-direct": {
      "command": "/path/to/mcp-ox-security",
      "env": {
        "OX_API_TOKEN": "your-token-here"
      }
    }
  }
}
```

## Example prompts

Once connected, you can ask the agent:

- "Get OX issue 019df5af-7053-7007-a115-aa40ac0d8b51"
- "Show me the issue graph for that finding"
- "Search for High severity issues owned by team@example.com"
- "List all applications for team@example.com"
- "What categories of issues does my-team have? Show breakdown"
- "List CVEs affecting the my-frontend-app app"
- "Show vulnerable libraries for my-team's apps"
- "What's blocking my pipeline?"
- "Show issues first seen after 2024-07-01 with severity Critical"
- "Get the SBOM for my-backend-app"

## Development

```bash
make build    # compile
make test     # run tests
make check    # full quality gate (fmt, vet, lint, vuln, complexity, tests)
make release  # cross-compile for distribution
```
