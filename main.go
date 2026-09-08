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

	// Severity bounds for change_severity: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical, 5=Appox.
	severityMin = 0
	severityMax = 5
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

type GetSbomLibraryDetailsInput struct {
	AppID       string `json:"app_id" jsonschema:"Application identifier (the appId field from get_sbom results)"`
	SbomID      string `json:"sbom_id,omitempty" jsonschema:"The library's id field from get_sbom results. Most precise identifier; pinpoints the exact library version"`
	LibID       string `json:"lib_id,omitempty" jsonschema:"Internal library identifier (libId from get_sbom results)"`
	LibraryName string `json:"library_name,omitempty" jsonschema:"Exact library name. May be ambiguous if the app has multiple versions of the same library"`
	Library     string `json:"library,omitempty" jsonschema:"Library name search term (fallback when no id is available)"`
	ScanID      string `json:"scan_id,omitempty" jsonschema:"Retrieve the library from a specific scan execution"`
}

type AddCommentToIssueInput struct {
	IssueID string `json:"issue_id" jsonschema:"The unique OX issue identifier to add a comment to"`
	Comment string `json:"comment" jsonschema:"The comment text to add to the issue. Cannot be empty"`
}

type ChangeSeverityInput struct {
	IssueID  string `json:"issue_id" jsonschema:"The unique OX issue identifier whose severity should be overridden"`
	Severity int    `json:"severity" jsonschema:"New severity level. Values: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical, 5=Appox"`
}

type ReportFalsePositiveInput struct {
	OxIssueID string `json:"ox_issue_id" jsonschema:"The unique OX issue identifier to mark as a false positive (returned as issueId in scan-issue queries)"`
	Comment   string `json:"comment" jsonschema:"Comment explaining why this issue is a false positive"`
}

type ReportFalsePositivePipelineInput struct {
	OxIssueID string `json:"ox_issue_id" jsonschema:"The unique OX issue identifier of the pipeline issue to mark as a false positive (returned as issueId in pipeline-issue queries)"`
	Comment   string `json:"comment" jsonschema:"Comment explaining why this pipeline issue is a false positive"`
}

type ExcludeIssuesInput struct {
	IssueIDs  []string `json:"issue_ids" jsonschema:"List of OX issue IDs to exclude. At least one ID is required"`
	Comment   string   `json:"comment,omitempty" jsonschema:"Optional comment explaining the reason for the exclusion"`
	ExpiredAt string   `json:"expired_at,omitempty" jsonschema:"Optional expiry date in ISO 8601 format (YYYY-MM-DDTHH:mm:ss.SSSZ). If omitted, the exclusion does not expire"`
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

// buildSearchFilters constructs conditionalFilters from SearchIssuesInput fields.
func buildSearchFilters(input SearchIssuesInput) []map[string]any {
	var filters []map[string]any

	fieldMappings := []struct {
		value     string
		fieldName string
	}{
		{input.Owner, "appOwnersEmail"},
		{input.Severity, "criticality"},
		{input.Category, "categories"},
		{input.AppName, "apps"},
		{input.Status, "issueStatus"},
		{input.SLA, "slaStatus"},
		{input.CVE, "cve"},
	}

	for _, m := range fieldMappings {
		if m.value != "" {
			filters = append(filters, map[string]any{
				"condition": "OR", "fieldName": m.fieldName, "values": []string{m.value},
			})
		}
	}

	if input.FirstSeenAfter != "" || input.FirstSeenBefore != "" {
		f := map[string]any{
			"condition": "OR", "fieldName": "firstSeen",
		}
		if input.FirstSeenAfter != "" {
			if t, parseErr := time.Parse("2006-01-02", input.FirstSeenAfter); parseErr == nil {
				f["greaterThan"] = float64(t.UnixMilli())
			}
		}
		if input.FirstSeenBefore != "" {
			if t, parseErr := time.Parse("2006-01-02", input.FirstSeenBefore); parseErr == nil {
				f["lessThan"] = float64(t.UnixMilli())
			}
		}
		filters = append(filters, f)
	}

	return filters
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

	if filters := buildSearchFilters(input); len(filters) > 0 {
		issuesInput["conditionalFilters"] = filters
	}

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

func getSbomLibraryDetails(ctx context.Context, _ *mcp.CallToolRequest, input GetSbomLibraryDetailsInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	libInput := map[string]any{
		"appId": input.AppID,
	}
	if input.SbomID != "" {
		// The GraphQL input names the field "libId" for the library's id in some
		// deployments; the docs expose "libId" plus name-based lookups. Pass the
		// most precise identifier the caller provided.
		libInput["libId"] = input.SbomID
	}
	if input.LibID != "" {
		libInput["libId"] = input.LibID
	}
	if input.LibraryName != "" {
		libInput["libraryName"] = input.LibraryName
	}
	if input.Library != "" {
		libInput["library"] = input.Library
	}
	if input.ScanID != "" {
		libInput["scanId"] = input.ScanID
	}

	variables := map[string]any{
		"getSingleSbomLibraryInput": libInput,
	}

	data, err := c.Execute(ctx, client.QueryGetSingleSbomLibrary, variables)
	if err != nil {
		return errorResult(fmt.Sprintf("OX API error: %v", err)), RawOutput{}, nil
	}

	return textResult(formatJSON(data)), RawOutput{}, nil
}

func addCommentToIssue(ctx context.Context, _ *mcp.CallToolRequest, input AddCommentToIssueInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	if input.IssueID == "" || input.Comment == "" {
		return errorResult("issue_id and comment are required"), RawOutput{}, nil
	}

	variables := map[string]any{
		"input": map[string]any{
			"issueId": input.IssueID,
			"comment": input.Comment,
		},
	}

	data, err := c.Execute(ctx, client.MutationAddCommentToIssue, variables)
	if err != nil {
		return errorResult(fmt.Sprintf("OX API error: %v", err)), RawOutput{}, nil
	}

	return textResult(formatJSON(data)), RawOutput{}, nil
}

func changeSeverity(ctx context.Context, _ *mcp.CallToolRequest, input ChangeSeverityInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	if input.IssueID == "" {
		return errorResult("issue_id is required"), RawOutput{}, nil
	}
	if input.Severity < severityMin || input.Severity > severityMax {
		return errorResult("severity must be between 0 (Info) and 5 (Appox)"), RawOutput{}, nil
	}

	variables := map[string]any{
		"input": map[string]any{
			"issueId":  input.IssueID,
			"severity": input.Severity,
		},
	}

	data, err := c.Execute(ctx, client.MutationUpdateIssueSeverity, variables)
	if err != nil {
		return errorResult(fmt.Sprintf("OX API error: %v", err)), RawOutput{}, nil
	}

	return textResult(formatJSON(data)), RawOutput{}, nil
}

// buildFalsePositiveVars builds the ReportFalsePositiveInput for the false-positive
// mutations. It mirrors the official MCP behavior: issue-level rule, create exclusion.
func buildFalsePositiveVars(oxIssueID, comment string) map[string]any {
	return map[string]any{
		"input": map[string]any{
			"reportedAlertInput": map[string]any{
				"oxIssueId": oxIssueID,
				"rule": map[string]any{
					"oxRuleId":    "issue",
					"aggIds":      []string{},
					"cvesAndLibs": []any{},
				},
				"comment":       comment,
				"exclusionMode": "fullScan",
			},
			"isExclude": true,
		},
	}
}

func reportFalsePositive(ctx context.Context, _ *mcp.CallToolRequest, input ReportFalsePositiveInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	if input.OxIssueID == "" || input.Comment == "" {
		return errorResult("ox_issue_id and comment are required"), RawOutput{}, nil
	}

	variables := buildFalsePositiveVars(input.OxIssueID, input.Comment)

	data, err := c.Execute(ctx, client.MutationReportFalsePositive, variables)
	if err != nil {
		return errorResult(fmt.Sprintf("OX API error: %v", err)), RawOutput{}, nil
	}

	return textResult(formatJSON(data)), RawOutput{}, nil
}

func reportFalsePositivePipeline(ctx context.Context, _ *mcp.CallToolRequest, input ReportFalsePositivePipelineInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	if input.OxIssueID == "" || input.Comment == "" {
		return errorResult("ox_issue_id and comment are required"), RawOutput{}, nil
	}

	variables := buildFalsePositiveVars(input.OxIssueID, input.Comment)

	data, err := c.Execute(ctx, client.MutationReportFalsePositiveForPipelineIssues, variables)
	if err != nil {
		return errorResult(fmt.Sprintf("OX API error: %v", err)), RawOutput{}, nil
	}

	return textResult(formatJSON(data)), RawOutput{}, nil
}

func excludeIssues(ctx context.Context, _ *mcp.CallToolRequest, input ExcludeIssuesInput) (*mcp.CallToolResult, RawOutput, error) {
	c := client.Get()

	if len(input.IssueIDs) == 0 {
		return errorResult("at least one issue_id is required"), RawOutput{}, nil
	}

	excludeInput := map[string]any{
		"issueIds": input.IssueIDs,
	}
	if input.Comment != "" {
		excludeInput["comment"] = input.Comment
	}
	if input.ExpiredAt != "" {
		excludeInput["expiredAt"] = input.ExpiredAt
	}

	variables := map[string]any{
		"input": excludeInput,
	}

	data, err := c.Execute(ctx, client.MutationExcludeIssues, variables)
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

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_sbom_library_details",
		Description: "Get full details for a single SBOM library, including its complete CVE list. Use this to drill into a library returned by get_sbom (which only returns vulnerability counts). Identify the library with app_id plus the most precise identifier available: sbom_id (the library's id), lib_id, or library_name.",
	}, getSbomLibraryDetails)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "add_comment_to_issue",
		Description: "Add a comment to an OX issue. Use this to record investigation notes, ownership decisions, or audit-trail context. This is a write operation that modifies the issue in OX Security.",
	}, addCommentToIssue)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "change_severity",
		Description: "Override the severity assigned to an OX issue (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical, 5=Appox). The override applies until manually reverted. This is a write operation that modifies the issue in OX Security.",
	}, changeSeverity)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "report_false_positive",
		Description: "Report a regular (active scan) issue as a false positive, with a comment explaining the reason. Does NOT support pipeline issues; use report_false_positive_pipeline for those. This is a write operation that creates an exclusion in OX Security.",
	}, reportFalsePositive)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "report_false_positive_pipeline",
		Description: "Report a CI/CD pipeline issue as a false positive, with a comment. Use report_false_positive for active (scan) issues instead. This is a write operation that creates an exclusion in OX Security.",
	}, reportFalsePositivePipeline)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "exclude_issues",
		Description: "Create exclusions for one or more issues in bulk, with an optional comment and expiry date. Excluded issues no longer appear in active issue queries until the exclusion expires or is removed. This is a write operation that modifies OX Security state.",
	}, excludeIssues)

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
