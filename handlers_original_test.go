package main

import (
	"context"
	"strings"
	"testing"
)

// This file backfills handler tests for the original 11 tools. It reuses the
// fake-server helpers defined in handlers_test.go (capturedRequest, newFakeOX,
// inputOf).

// findFilter returns the first conditionalFilter with the given fieldName, or nil.
func findFilter(filters []any, fieldName string) map[string]any {
	for _, f := range filters {
		m, ok := f.(map[string]any)
		if !ok {
			continue
		}
		if m["fieldName"] == fieldName {
			return m
		}
	}
	return nil
}

// conditionalFiltersOf extracts conditionalFilters from a nested input object.
func conditionalFiltersOf(t *testing.T, obj map[string]any) []any {
	t.Helper()
	raw, ok := obj["conditionalFilters"].([]any)
	if !ok {
		t.Fatalf("expected conditionalFilters array, got: %v", obj["conditionalFilters"])
	}
	return raw
}

func TestGetIssue_WrapsSingleIssueInput(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := getIssue(context.Background(), nil, GetIssueInput{IssueID: "issue-1"})
	if err != nil || res.IsError {
		t.Fatalf("unexpected failure: err=%v res=%+v", err, res)
	}
	if !strings.Contains(got.Query, "getSingleIssueInfo") {
		t.Errorf("expected getSingleIssueInfo, got: %s", got.Query)
	}
	in, ok := got.Variables["getSingleIssueInput"].(map[string]any)
	if !ok || in["issueId"] != "issue-1" {
		t.Errorf("unexpected variables: %v", got.Variables)
	}
}

func TestGetIssueGraph_WrapsIssueId(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := getIssueGraph(context.Background(), nil, GetIssueGraphInput{IssueID: "issue-1"})
	if err != nil || res.IsError {
		t.Fatalf("unexpected failure: err=%v res=%+v", err, res)
	}
	if !strings.Contains(got.Query, "getIssueGraph") {
		t.Errorf("expected getIssueGraph, got: %s", got.Query)
	}
	if got.Variables["issueId"] != "issue-1" {
		t.Errorf("expected issueId var, got: %v", got.Variables)
	}
}

func TestGetIssuePrioritization_WrapsIssueId(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := getIssuePrioritization(context.Background(), nil, GetIssuePrioritizationInput{IssueID: "issue-1"})
	if err != nil || res.IsError {
		t.Fatalf("unexpected failure: err=%v res=%+v", err, res)
	}
	if !strings.Contains(got.Query, "getIssuePrioritization") {
		t.Errorf("expected getIssuePrioritization, got: %s", got.Query)
	}
	if got.Variables["issueId"] != "issue-1" {
		t.Errorf("expected issueId var, got: %v", got.Variables)
	}
}

func TestGetResolvedIssue_WrapsSingleIssueInput(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := getResolvedIssue(context.Background(), nil, GetResolvedIssueInput{IssueID: "issue-1"})
	if err != nil || res.IsError {
		t.Fatalf("unexpected failure: err=%v res=%+v", err, res)
	}
	if !strings.Contains(got.Query, "getResolvedIssue") {
		t.Errorf("expected getResolvedIssue, got: %s", got.Query)
	}
	in, ok := got.Variables["getSingleIssueInput"].(map[string]any)
	if !ok || in["issueId"] != "issue-1" {
		t.Errorf("unexpected variables: %v", got.Variables)
	}
}

func TestGetRemovedIssue_WrapsDisappearedInput(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := getRemovedIssue(context.Background(), nil, GetRemovedIssueInput{IssueID: "issue-1"})
	if err != nil || res.IsError {
		t.Fatalf("unexpected failure: err=%v res=%+v", err, res)
	}
	if !strings.Contains(got.Query, "getRemovedIssue") {
		t.Errorf("expected getRemovedIssue, got: %s", got.Query)
	}
	in, ok := got.Variables["getSingleDisappearedIssueInput"].(map[string]any)
	if !ok || in["issueId"] != "issue-1" {
		t.Errorf("unexpected variables: %v", got.Variables)
	}
}

func TestSearchIssues_DefaultLimitAndFilters(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := searchIssues(context.Background(), nil, SearchIssuesInput{
		Owner:    "team@example.com",
		Severity: "High",
		Category: "Code Security",
		AppName:  "my-app",
		Status:   "open",
		SLA:      "Within",
		CVE:      "CVE-2024-1234",
		Title:    "Untrusted",
	})
	if err != nil || res.IsError {
		t.Fatalf("unexpected failure: err=%v res=%+v", err, res)
	}
	if !strings.Contains(got.Query, "getIssues") {
		t.Errorf("expected getIssues, got: %s", got.Query)
	}
	in, ok := got.Variables["getIssuesInput"].(map[string]any)
	if !ok {
		t.Fatalf("expected getIssuesInput object, got: %v", got.Variables)
	}
	if lim, _ := in["limit"].(float64); lim != 10 {
		t.Errorf("expected default limit 10, got: %v", in["limit"])
	}
	if in["naturalSearch"] != "Issue name is Untrusted" {
		t.Errorf("expected title mapped to naturalSearch, got: %v", in["naturalSearch"])
	}
	filters := conditionalFiltersOf(t, in)
	// Verify field-name mappings.
	checks := map[string]string{
		"appOwnersEmail": "team@example.com",
		"criticality":    "High",
		"categories":     "Code Security",
		"apps":           "my-app",
		"issueStatus":    "open",
		"slaStatus":      "Within",
		"cve":            "CVE-2024-1234",
	}
	for field, want := range checks {
		f := findFilter(filters, field)
		if f == nil {
			t.Errorf("missing filter for field %s", field)
			continue
		}
		vals, ok := f["values"].([]any)
		if !ok || len(vals) != 1 || vals[0] != want {
			t.Errorf("filter %s: expected [%s], got: %v", field, want, f["values"])
		}
	}
}

func TestSearchIssues_DateRangeFilter(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := searchIssues(context.Background(), nil, SearchIssuesInput{
		FirstSeenAfter:  "2024-01-01",
		FirstSeenBefore: "2024-12-31",
		Limit:           25,
	})
	if err != nil || res.IsError {
		t.Fatalf("unexpected failure: err=%v res=%+v", err, res)
	}
	in := got.Variables["getIssuesInput"].(map[string]any)
	if lim, _ := in["limit"].(float64); lim != 25 {
		t.Errorf("expected limit 25, got: %v", in["limit"])
	}
	f := findFilter(conditionalFiltersOf(t, in), "firstSeen")
	if f == nil {
		t.Fatal("expected firstSeen filter")
	}
	// 2024-01-01 in ms = 1704067200000; 2024-12-31 = 1735603200000.
	if gt, _ := f["greaterThan"].(float64); gt != 1704067200000 {
		t.Errorf("unexpected greaterThan: %v", f["greaterThan"])
	}
	if lt, _ := f["lessThan"].(float64); lt != 1735603200000 {
		t.Errorf("unexpected lessThan: %v", f["lessThan"])
	}
}

func TestSearchIssues_NoFiltersOmitsConditionalFilters(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := searchIssues(context.Background(), nil, SearchIssuesInput{})
	if err != nil || res.IsError {
		t.Fatalf("unexpected failure: err=%v res=%+v", err, res)
	}
	in := got.Variables["getIssuesInput"].(map[string]any)
	if _, present := in["conditionalFilters"]; present {
		t.Errorf("expected no conditionalFilters when no filters given, got: %v", in["conditionalFilters"])
	}
}

func TestGetIssueFilters_DefaultFacets(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := getIssueFilters(context.Background(), nil, GetIssueFiltersInput{})
	if err != nil || res.IsError {
		t.Fatalf("unexpected failure: err=%v res=%+v", err, res)
	}
	if !strings.Contains(got.Query, "getIssuesConditionalFiltersLazy") {
		t.Errorf("expected getIssuesConditionalFiltersLazy, got: %s", got.Query)
	}
	in := got.Variables["getIssuesInput"].(map[string]any)
	items, ok := in["openItems"].([]any)
	if !ok {
		t.Fatalf("expected openItems array, got: %v", in["openItems"])
	}
	want := []string{"categories", "criticality", "apps", "slaStatus"}
	if len(items) != len(want) {
		t.Fatalf("expected %d default facets, got: %v", len(want), items)
	}
	for i, w := range want {
		if items[i] != w {
			t.Errorf("facet %d: expected %s, got %v", i, w, items[i])
		}
	}
}

func TestGetIssueFilters_CustomFacetsAndScope(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := getIssueFilters(context.Background(), nil, GetIssueFiltersInput{
		Owner:   "team@example.com",
		AppName: "my-app",
		Facets:  "cve, languages",
	})
	if err != nil || res.IsError {
		t.Fatalf("unexpected failure: err=%v res=%+v", err, res)
	}
	in := got.Variables["getIssuesInput"].(map[string]any)
	items := in["openItems"].([]any)
	if len(items) != 2 || items[0] != "cve" || items[1] != "languages" {
		t.Errorf("expected trimmed [cve languages], got: %v", items)
	}
	filters := conditionalFiltersOf(t, in)
	if findFilter(filters, "appOwnersEmail") == nil || findFilter(filters, "apps") == nil {
		t.Errorf("expected owner and app filters, got: %v", filters)
	}
}

func TestGetSbom_DefaultLimitAndSearch(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := getSbom(context.Background(), nil, GetSbomInput{
		AppName: "my-app",
		Owner:   "team@example.com",
		Search:  "lodash",
	})
	if err != nil || res.IsError {
		t.Fatalf("unexpected failure: err=%v res=%+v", err, res)
	}
	if !strings.Contains(got.Query, "getSbom") {
		t.Errorf("expected getSbom, got: %s", got.Query)
	}
	in := got.Variables["getSbomInput"].(map[string]any)
	if lim, _ := in["limit"].(float64); lim != 20 {
		t.Errorf("expected default limit 20, got: %v", in["limit"])
	}
	if in["search"] != "lodash" {
		t.Errorf("expected search lodash, got: %v", in["search"])
	}
	filters := conditionalFiltersOf(t, in)
	if findFilter(filters, "apps") == nil || findFilter(filters, "appOwnersEmail") == nil {
		t.Errorf("expected apps and appOwnersEmail filters, got: %v", filters)
	}
}

func TestGetVulnerableLibraries_UsesVulnQuery(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := getVulnerableLibraries(context.Background(), nil, GetVulnerableLibrariesInput{AppName: "my-app"})
	if err != nil || res.IsError {
		t.Fatalf("unexpected failure: err=%v res=%+v", err, res)
	}
	if !strings.Contains(got.Query, "getSbomVulnerableLibraries") {
		t.Errorf("expected getSbomVulnerableLibraries, got: %s", got.Query)
	}
	in := got.Variables["getSbomInput"].(map[string]any)
	if lim, _ := in["limit"].(float64); lim != 20 {
		t.Errorf("expected default limit 20, got: %v", in["limit"])
	}
}

func TestGetPipelineIssues_SeverityFilter(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := getPipelineIssues(context.Background(), nil, GetPipelineIssuesInput{
		AppName:  "my-app",
		Severity: "Critical",
	})
	if err != nil || res.IsError {
		t.Fatalf("unexpected failure: err=%v res=%+v", err, res)
	}
	if !strings.Contains(got.Query, "getCICDIssues") {
		t.Errorf("expected getCICDIssues, got: %s", got.Query)
	}
	in := got.Variables["getCICDIssuesInput"].(map[string]any)
	if lim, _ := in["limit"].(float64); lim != 10 {
		t.Errorf("expected default limit 10, got: %v", in["limit"])
	}
	filters := conditionalFiltersOf(t, in)
	crit := findFilter(filters, "criticality")
	if crit == nil {
		t.Fatal("expected criticality filter")
	}
	if vals, _ := crit["values"].([]any); len(vals) != 1 || vals[0] != "Critical" {
		t.Errorf("expected criticality [Critical], got: %v", crit["values"])
	}
}

func TestListApplications_OwnerAndSearch(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := listApplications(context.Background(), nil, ListApplicationsInput{
		Search: "front",
		Owner:  "team@example.com",
	})
	if err != nil || res.IsError {
		t.Fatalf("unexpected failure: err=%v res=%+v", err, res)
	}
	if !strings.Contains(got.Query, "getApplications") {
		t.Errorf("expected getApplications, got: %s", got.Query)
	}
	in := got.Variables["getApplicationsInput"].(map[string]any)
	if lim, _ := in["limit"].(float64); lim != 50 {
		t.Errorf("expected default limit 50, got: %v", in["limit"])
	}
	if in["search"] != "front" {
		t.Errorf("expected search front, got: %v", in["search"])
	}
	owners, ok := in["owners"].([]any)
	if !ok || len(owners) != 1 || owners[0] != "team@example.com" {
		t.Errorf("expected owners [team@example.com], got: %v", in["owners"])
	}
}
