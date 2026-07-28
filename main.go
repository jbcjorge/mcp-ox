package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jbcjorge/mcp-ox/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var version = "dev"

const (
	defaultAddr      = ":8080"
	httpReadTimeout  = 30 * time.Second
	httpWriteTimeout = 60 * time.Second
	httpIdleTimeout  = 120 * time.Second
)

// Tool input types.

type GetIssueInput struct {
	IssueID string `json:"issue_id" jsonschema:"The unique OX issue ID (UUID)"`
}

type GetIssueGraphInput struct {
	IssueID string `json:"issue_id" jsonschema:"The unique OX issue ID to get the relationship graph for"`
}

type SearchIssuesInput struct {
	AppName         string `json:"app_name,omitempty" jsonschema:"Filter by application name"`
	Severity        string `json:"severity,omitempty" jsonschema:"Filter by severity level (Critical/High/Medium/Low/Info)"`
	Category        string `json:"category,omitempty" jsonschema:"Filter by category (e.g. Code Security, Open Source Security, Infrastructure as Code Scan)"`
	Title           string `json:"title,omitempty" jsonschema:"Filter by issue title (partial match)"`
	Owner           string `json:"owner,omitempty" jsonschema:"Filter by owner email (e.g. team@example.com)"`
	Status          string `json:"status,omitempty" jsonschema:"Filter by issue status (e.g. open, resolved, removed)"`
	SLA             string `json:"sla,omitempty" jsonschema:"Filter by SLA status (e.g. Within, Exceeded)"`
	CVE             string `json:"cve,omitempty" jsonschema:"Filter by CVE identifier (e.g. CVE-2024-1234)"`
	FirstSeenAfter  string `json:"first_seen_after,omitempty" jsonschema:"Filter issues first seen after this date (ISO 8601, e.g. 2024-01-15)"`
	FirstSeenBefore string `json:"first_seen_before,omitempty" jsonschema:"Filter issues first seen before this date (ISO 8601, e.g. 2024-06-30)"`
	Limit           int    `json:"limit,omitempty" jsonschema:"Max results to return (default 10)"`
	Offset          int    `json:"offset,omitempty" jsonschema:"Pagination offset (default 0)"`
}

type GetResolvedIssueInput struct {
	IssueID string `json:"issue_id" jsonschema:"The unique OX issue ID of the resolved issue"`
}

type GetRemovedIssueInput struct {
	IssueID string `json:"issue_id" jsonschema:"The unique OX issue ID of the removed/disappeared issue"`
}

type GetIssuePrioritizationInput struct {
	IssueID string `json:"issue_id" jsonschema:"The unique OX issue ID to get prioritization data for"`
}

type ListApplicationsInput struct {
	Search string `json:"search,omitempty" jsonschema:"Search applications by name (partial match)"`
	Owner  string `json:"owner,omitempty" jsonschema:"Filter by owner email (e.g. team@example.com)"`
	Limit  int    `json:"limit,omitempty" jsonschema:"Max results to return (default 50)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Pagination offset (default 0)"`
}

type GetIssueFiltersInput struct {
	Owner   string `json:"owner,omitempty" jsonschema:"Scope breakdown to an owner email"`
	AppName string `json:"app_name,omitempty" jsonschema:"Scope breakdown to a specific application"`
	Facets  string `json:"facets,omitempty" jsonschema:"Comma-separated facets to retrieve (default: categories,criticality,apps,slaStatus). Available: categories,criticality,apps,slaStatus,sourceTools,issueOwners,cve,languages,severityChangeReasons,appOwnersName"`
}

type GetSbomInput struct {
	AppName string `json:"app_name,omitempty" jsonschema:"Filter SBOM by application name"`
	Owner   string `json:"owner,omitempty" jsonschema:"Filter SBOM by owner email"`
	Search  string `json:"search,omitempty" jsonschema:"Search libraries by name"`
	Limit   int    `json:"limit,omitempty" jsonschema:"Max results to return (default 20)"`
	Offset  int    `json:"offset,omitempty" jsonschema:"Pagination offset (default 0)"`
}

type GetVulnerableLibrariesInput struct {
	AppName string `json:"app_name,omitempty" jsonschema:"Filter by application name"`
	Owner   string `json:"owner,omitempty" jsonschema:"Filter by owner email"`
	Search  string `json:"search,omitempty" jsonschema:"Search vulnerable libraries by name"`
	Limit   int    `json:"limit,omitempty" jsonschema:"Max results to return (default 20)"`
	Offset  int    `json:"offset,omitempty" jsonschema:"Pagination offset (default 0)"`
}

type GetPipelineIssuesInput struct {
	AppName  string `json:"app_name,omitempty" jsonschema:"Filter by application name"`
	Owner    string `json:"owner,omitempty" jsonschema:"Filter by owner email"`
	Severity string `json:"severity,omitempty" jsonschema:"Filter by severity (Critical/High/Medium/Low/Info)"`
	Limit    int    `json:"limit,omitempty" jsonschema:"Max results to return (default 10)"`
	Offset   int    `json:"offset,omitempty" jsonschema:"Pagination offset (default 0)"`
}

// RawOutput is an empty output struct; we return raw JSON via CallToolResult.
type RawOutput struct{}

func formatJSON(data json.RawMessage) string {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err != nil {
		return string(data)
	}
	return pretty.String()
}

// Tool handlers.

func getIssue(ctx context.Context, _ *mcp.CallToolRequest, input GetIssueInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	variables := map[string]any{
		"getSingleIssueInput": map[string]any{
			"issueId": input.IssueID,
		},
	}

	data, err := c.Execute(ctx, client.QueryGetSingleIssueInfo, variables)
	if err != nil {
		return errorResult(fmt.Sprintf("OX API error: %v", err)), RawOutput{}, nil
	}

	return textResult(formatJSON(data)), RawOutput{}, nil
}

func getIssueGraph(ctx context.Context, _ *mcp.CallToolRequest, input GetIssueGraphInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	variables := map[string]any{
		"issueId": input.IssueID,
	}

	data, err := c.Execute(ctx, client.QueryGetIssueGraph, variables)
	if err != nil {
		return errorResult(fmt.Sprintf("OX API error: %v", err)), RawOutput{}, nil
	}

	return textResult(formatJSON(data)), RawOutput{}, nil
}

func searchIssues(ctx context.Context, _ *mcp.CallToolRequest, input SearchIssuesInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	limit := input.Limit
	if limit <= 0 {
		limit = 10
	}

	issuesInput := map[string]any{
		"limit":  limit,
		"offset": input.Offset,
	}

	// Build conditionalFilters for structured fields.
	var filters []map[string]any
	if input.Owner != "" {
		filters = append(filters, map[string]any{
			"condition": "OR", "fieldName": "appOwnersEmail", "values": []string{input.Owner},
		})
	}
	if input.Severity != "" {
		filters = append(filters, map[string]any{
			"condition": "OR", "fieldName": "criticality", "values": []string{input.Severity},
		})
	}
	if input.Category != "" {
		filters = append(filters, map[string]any{
			"condition": "OR", "fieldName": "categories", "values": []string{input.Category},
		})
	}
	if input.AppName != "" {
		filters = append(filters, map[string]any{
			"condition": "OR", "fieldName": "apps", "values": []string{input.AppName},
		})
	}
	if input.Status != "" {
		filters = append(filters, map[string]any{
			"condition": "OR", "fieldName": "issueStatus", "values": []string{input.Status},
		})
	}
	if input.SLA != "" {
		filters = append(filters, map[string]any{
			"condition": "OR", "fieldName": "slaStatus", "values": []string{input.SLA},
		})
	}
	if input.CVE != "" {
		filters = append(filters, map[string]any{
			"condition": "OR", "fieldName": "cve", "values": []string{input.CVE},
		})
	}
	if input.FirstSeenAfter != "" || input.FirstSeenBefore != "" {
		f := map[string]any{
			"condition": "OR", "fieldName": "firstSeen",
		}
		if input.FirstSeenAfter != "" {
			if t, err := time.Parse("2006-01-02", input.FirstSeenAfter); err == nil {
				f["greaterThan"] = float64(t.UnixMilli())
			}
		}
		if input.FirstSeenBefore != "" {
			if t, err := time.Parse("2006-01-02", input.FirstSeenBefore); err == nil {
				f["lessThan"] = float64(t.UnixMilli())
			}
		}
		filters = append(filters, f)
	}
	if len(filters) > 0 {
		issuesInput["conditionalFilters"] = filters
	}

	// Title goes into naturalSearch (free-text).
	if input.Title != "" {
		issuesInput["naturalSearch"] = fmt.Sprintf("Issue name is %s", input.Title)
	}

	variables := map[string]any{
		"getIssuesInput": issuesInput,
	}

	data, err := c.Execute(ctx, client.QuerySearchIssues, variables)
	if err != nil {
		return errorResult(fmt.Sprintf("OX API error: %v", err)), RawOutput{}, nil
	}

	return textResult(formatJSON(data)), RawOutput{}, nil
}

func getResolvedIssue(ctx context.Context, _ *mcp.CallToolRequest, input GetResolvedIssueInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	variables := map[string]any{
		"getSingleIssueInput": map[string]any{
			"issueId": input.IssueID,
		},
	}

	data, err := c.Execute(ctx, client.QueryGetResolvedIssue, variables)
	if err != nil {
		return errorResult(fmt.Sprintf("OX API error: %v", err)), RawOutput{}, nil
	}

	return textResult(formatJSON(data)), RawOutput{}, nil
}

func getRemovedIssue(ctx context.Context, _ *mcp.CallToolRequest, input GetRemovedIssueInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	variables := map[string]any{
		"getSingleDisappearedIssueInput": map[string]any{
			"issueId": input.IssueID,
		},
	}

	data, err := c.Execute(ctx, client.QueryGetRemovedIssue, variables)
	if err != nil {
		return errorResult(fmt.Sprintf("OX API error: %v", err)), RawOutput{}, nil
	}

	return textResult(formatJSON(data)), RawOutput{}, nil
}

func getIssuePrioritization(ctx context.Context, _ *mcp.CallToolRequest, input GetIssuePrioritizationInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	variables := map[string]any{
		"issueId": input.IssueID,
	}

	data, err := c.Execute(ctx, client.QueryGetIssuePrioritization, variables)
	if err != nil {
		return errorResult(fmt.Sprintf("OX API error: %v", err)), RawOutput{}, nil
	}

	return textResult(formatJSON(data)), RawOutput{}, nil
}

// Helpers.

func getIssueFilters(ctx context.Context, _ *mcp.CallToolRequest, input GetIssueFiltersInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	// Default facets.
	facets := "categories,criticality,apps,slaStatus"
	if input.Facets != "" {
		facets = input.Facets
	}

	var openItems []string
	for _, f := range strings.Split(facets, ",") {
		openItems = append(openItems, strings.TrimSpace(f))
	}

	issuesInput := map[string]any{
		"limit":     50,
		"offset":    0,
		"openItems": openItems,
	}

	var filters []map[string]any
	if input.Owner != "" {
		filters = append(filters, map[string]any{
			"condition": "OR", "fieldName": "appOwnersEmail", "values": []string{input.Owner},
		})
	}
	if input.AppName != "" {
		filters = append(filters, map[string]any{
			"condition": "OR", "fieldName": "apps", "values": []string{input.AppName},
		})
	}
	if len(filters) > 0 {
		issuesInput["conditionalFilters"] = filters
	}

	variables := map[string]any{
		"getIssuesInput": issuesInput,
	}

	data, err := c.Execute(ctx, client.QueryGetIssueFilters, variables)
	if err != nil {
		return errorResult(fmt.Sprintf("OX API error: %v", err)), RawOutput{}, nil
	}

	return textResult(formatJSON(data)), RawOutput{}, nil
}

func getSbom(ctx context.Context, _ *mcp.CallToolRequest, input GetSbomInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	limit := input.Limit
	if limit <= 0 {
		limit = 20
	}

	sbomInput := map[string]any{
		"limit":  limit,
		"offset": input.Offset,
	}

	var filters []map[string]any
	if input.AppName != "" {
		filters = append(filters, map[string]any{
			"condition": "OR", "fieldName": "apps", "values": []string{input.AppName},
		})
	}
	if input.Owner != "" {
		filters = append(filters, map[string]any{
			"condition": "OR", "fieldName": "appOwnersEmail", "values": []string{input.Owner},
		})
	}
	if len(filters) > 0 {
		sbomInput["conditionalFilters"] = filters
	}
	if input.Search != "" {
		sbomInput["search"] = input.Search
	}

	variables := map[string]any{
		"getSbomInput": sbomInput,
	}

	data, err := c.Execute(ctx, client.QueryGetSbom, variables)
	if err != nil {
		return errorResult(fmt.Sprintf("OX API error: %v", err)), RawOutput{}, nil
	}

	return textResult(formatJSON(data)), RawOutput{}, nil
}

func getVulnerableLibraries(ctx context.Context, _ *mcp.CallToolRequest, input GetVulnerableLibrariesInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	limit := input.Limit
	if limit <= 0 {
		limit = 20
	}

	sbomInput := map[string]any{
		"limit":  limit,
		"offset": input.Offset,
	}

	var filters []map[string]any
	if input.AppName != "" {
		filters = append(filters, map[string]any{
			"condition": "OR", "fieldName": "apps", "values": []string{input.AppName},
		})
	}
	if input.Owner != "" {
		filters = append(filters, map[string]any{
			"condition": "OR", "fieldName": "appOwnersEmail", "values": []string{input.Owner},
		})
	}
	if len(filters) > 0 {
		sbomInput["conditionalFilters"] = filters
	}
	if input.Search != "" {
		sbomInput["search"] = input.Search
	}

	variables := map[string]any{
		"getSbomInput": sbomInput,
	}

	data, err := c.Execute(ctx, client.QueryGetVulnerableLibraries, variables)
	if err != nil {
		return errorResult(fmt.Sprintf("OX API error: %v", err)), RawOutput{}, nil
	}

	return textResult(formatJSON(data)), RawOutput{}, nil
}

func getPipelineIssues(ctx context.Context, _ *mcp.CallToolRequest, input GetPipelineIssuesInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	limit := input.Limit
	if limit <= 0 {
		limit = 10
	}

	cicdInput := map[string]any{
		"limit":  limit,
		"offset": input.Offset,
	}

	var filters []map[string]any
	if input.AppName != "" {
		filters = append(filters, map[string]any{
			"condition": "OR", "fieldName": "apps", "values": []string{input.AppName},
		})
	}
	if input.Owner != "" {
		filters = append(filters, map[string]any{
			"condition": "OR", "fieldName": "appOwnersEmail", "values": []string{input.Owner},
		})
	}
	if input.Severity != "" {
		filters = append(filters, map[string]any{
			"condition": "OR", "fieldName": "criticality", "values": []string{input.Severity},
		})
	}
	if len(filters) > 0 {
		cicdInput["conditionalFilters"] = filters
	}

	variables := map[string]any{
		"getCICDIssuesInput": cicdInput,
	}

	data, err := c.Execute(ctx, client.QueryGetPipelineIssues, variables)
	if err != nil {
		return errorResult(fmt.Sprintf("OX API error: %v", err)), RawOutput{}, nil
	}

	return textResult(formatJSON(data)), RawOutput{}, nil
}

func listApplications(ctx context.Context, _ *mcp.CallToolRequest, input ListApplicationsInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	limit := input.Limit
	if limit <= 0 {
		limit = 50
	}

	appsInput := map[string]any{
		"limit":  limit,
		"offset": input.Offset,
	}
	if input.Search != "" {
		appsInput["search"] = input.Search
	}
	if input.Owner != "" {
		appsInput["owners"] = []string{input.Owner}
	}

	variables := map[string]any{
		"getApplicationsInput": appsInput,
	}

	data, err := c.Execute(ctx, client.QueryGetApplications, variables)
	if err != nil {
		return errorResult(fmt.Sprintf("OX API error: %v", err)), RawOutput{}, nil
	}

	return textResult(formatJSON(data)), RawOutput{}, nil
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}
}

func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "Error: " + msg},
		},
		IsError: true,
	}
}

func newServer() *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "mcp-ox-security",
			Version: version,
		},
		nil,
	)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_issue",
		Description: "Get full details of a specific OX Security issue by its ID. Returns severity, description, affected app, code locations, recommendations, compliance info, and more.",
	}, getIssue)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_issue_graph",
		Description: "Get the relationship graph of an OX Security issue, showing connections to other entities, dependencies, and related components.",
	}, getIssueGraph)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "search_issues",
		Description: "Search OX Security issues with filters for application name, severity, category, and title. Returns a paginated list of matching issues.",
	}, searchIssues)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_resolved_issue",
		Description: "Get details of a resolved OX Security issue by its ID, including resolution reason and date.",
	}, getResolvedIssue)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_removed_issue",
		Description: "Get details of a removed/disappeared OX Security issue by its ID, including the reason it disappeared.",
	}, getRemovedIssue)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_issue_prioritization",
		Description: "Get prioritization data for an OX Security issue, showing how it ranks relative to other issues.",
	}, getIssuePrioritization)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_applications",
		Description: "List all applications in OX Security with their security posture, issue counts, owners, and risk scores. Filter by name or owner email.",
	}, listApplications)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_issue_filters",
		Description: "Get a breakdown of issues by category, severity, application, SLA status, and more. Optionally scope to a specific owner or application. Returns counts per facet value.",
	}, getIssueFilters)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_sbom",
		Description: "List SBOM (Software Bill of Materials) libraries for an application. Shows dependencies with versions, licenses, vulnerability counts, and maintenance status.",
	}, getSbom)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_vulnerable_libraries",
		Description: "List vulnerable SBOM libraries with CVE details, EPSS scores, fix versions, and exploit information. Filter by application or owner.",
	}, getVulnerableLibraries)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_pipeline_issues",
		Description: "List CI/CD pipeline security issues found during pipeline runs. Shows blocking/non-blocking findings with job details, PR links, and enforcement status.",
	}, getPipelineIssues)

	return server
}

func initLogging() {
	levelStr := os.Getenv("LOG_LEVEL")
	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}

func main() {
	initLogging()

	if err := client.Init(); err != nil {
		slog.Error("failed to initialize ox client", "err", err)
		os.Exit(1)
	}

	transport := os.Getenv("MCP_TRANSPORT")
	addr := os.Getenv("MCP_ADDR")
	if addr == "" {
		addr = defaultAddr
	}

	slog.Info("server starting", "transport", transport, "version", version)

	switch transport {
	case "http", "streamable-http":
		handler := mcp.NewStreamableHTTPHandler(
			func(r *http.Request) *mcp.Server { return newServer() },
			nil,
		)
		srv := &http.Server{
			Addr:         addr,
			Handler:      handler,
			ReadTimeout:  httpReadTimeout,
			WriteTimeout: httpWriteTimeout,
			IdleTimeout:  httpIdleTimeout,
		}
		slog.Info("listening", "addr", addr, "mode", "streamable-http")
		if err := srv.ListenAndServe(); err != nil {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}

	case "sse":
		handler := mcp.NewSSEHandler(
			func(r *http.Request) *mcp.Server { return newServer() },
			nil,
		)
		srv := &http.Server{
			Addr:         addr,
			Handler:      handler,
			ReadTimeout:  httpReadTimeout,
			WriteTimeout: httpWriteTimeout,
			IdleTimeout:  httpIdleTimeout,
		}
		slog.Info("listening", "addr", addr, "mode", "sse")
		if err := srv.ListenAndServe(); err != nil {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}

	default:
		server := newServer()
		if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
			slog.Error("server error", "transport", "stdio", "err", err)
			os.Exit(1)
		}
	}
}
