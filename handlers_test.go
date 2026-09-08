package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jbcjorge/mcp-ox/client"
)

// capturedRequest holds the GraphQL request body captured by the fake server.
type capturedRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

// newFakeOX starts a fake GraphQL server that records the request body into got
// and returns a minimal valid GraphQL data response. It re-initializes the client
// to point at the fake server.
func newFakeOX(t *testing.T, got *capturedRequest) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(got); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"ok": true},
		}); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))

	t.Setenv("OX_API_TOKEN", "test-token")
	t.Setenv("OX_API_URL", ts.URL)
	if err := client.Init(); err != nil {
		t.Fatalf("client init: %v", err)
	}
	return ts
}

// input extracts the "input" object from captured variables.
func inputOf(t *testing.T, got *capturedRequest) map[string]any {
	t.Helper()
	in, ok := got.Variables["input"].(map[string]any)
	if !ok {
		t.Fatalf("expected variables.input to be an object, got: %v", got.Variables)
	}
	return in
}

func TestGetSbomLibraryDetails_BuildsInput(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := getSbomLibraryDetails(context.Background(), nil, GetSbomLibraryDetailsInput{
		AppID:       "app-1",
		SbomID:      "sbom-1",
		LibraryName: "lodash",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %+v", res.Content)
	}
	if !strings.Contains(got.Query, "getSingleSbomLibrary") {
		t.Errorf("expected getSingleSbomLibrary in query, got: %s", got.Query)
	}
	in, ok := got.Variables["getSingleSbomLibraryInput"].(map[string]any)
	if !ok {
		t.Fatalf("expected getSingleSbomLibraryInput object, got: %v", got.Variables)
	}
	if in["appId"] != "app-1" || in["libId"] != "sbom-1" || in["libraryName"] != "lodash" {
		t.Errorf("unexpected input: %v", in)
	}
}

func TestAddCommentToIssue_BuildsInput(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := addCommentToIssue(context.Background(), nil, AddCommentToIssueInput{
		IssueID: "issue-1",
		Comment: "looks intentional",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %+v", res.Content)
	}
	if !strings.Contains(got.Query, "addCommentToIssue") {
		t.Errorf("expected addCommentToIssue in query, got: %s", got.Query)
	}
	in := inputOf(t, &got)
	if in["issueId"] != "issue-1" || in["comment"] != "looks intentional" {
		t.Errorf("unexpected input: %v", in)
	}
}

func TestAddCommentToIssue_Validation(t *testing.T) {
	// Empty comment must fail validation without calling the API.
	t.Setenv("OX_API_TOKEN", "test-token")
	t.Setenv("OX_API_URL", "http://127.0.0.1:0") // unreachable; must not be hit
	if err := client.Init(); err != nil {
		t.Fatalf("client init: %v", err)
	}
	res, _, err := addCommentToIssue(context.Background(), nil, AddCommentToIssueInput{IssueID: "x", Comment: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected validation error for empty comment")
	}
}

func TestChangeSeverity_BuildsInput(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := changeSeverity(context.Background(), nil, ChangeSeverityInput{
		IssueID:  "issue-1",
		Severity: 3,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %+v", res.Content)
	}
	if !strings.Contains(got.Query, "updateIssueSeverity") {
		t.Errorf("expected updateIssueSeverity in query, got: %s", got.Query)
	}
	in := inputOf(t, &got)
	if in["issueId"] != "issue-1" {
		t.Errorf("unexpected issueId: %v", in["issueId"])
	}
	// JSON numbers decode as float64.
	if sev, ok := in["severity"].(float64); !ok || sev != 3 {
		t.Errorf("expected severity 3, got: %v", in["severity"])
	}
}

func TestChangeSeverity_OutOfRange(t *testing.T) {
	t.Setenv("OX_API_TOKEN", "test-token")
	t.Setenv("OX_API_URL", "http://127.0.0.1:0")
	if err := client.Init(); err != nil {
		t.Fatalf("client init: %v", err)
	}
	for _, sev := range []int{-1, 6} {
		res, _, err := changeSeverity(context.Background(), nil, ChangeSeverityInput{IssueID: "x", Severity: sev})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.IsError {
			t.Errorf("expected out-of-range error for severity %d", sev)
		}
	}
}

func TestReportFalsePositive_BuildsInput(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := reportFalsePositive(context.Background(), nil, ReportFalsePositiveInput{
		OxIssueID: "issue-1",
		Comment:   "false positive: test fixture",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %+v", res.Content)
	}
	if !strings.Contains(got.Query, "reportAlertAsFalsePositive") {
		t.Errorf("expected reportAlertAsFalsePositive in query, got: %s", got.Query)
	}
	in := inputOf(t, &got)
	if in["isExclude"] != true {
		t.Errorf("expected isExclude true, got: %v", in["isExclude"])
	}
	rai, ok := in["reportedAlertInput"].(map[string]any)
	if !ok {
		t.Fatalf("expected reportedAlertInput object, got: %v", in)
	}
	if rai["oxIssueId"] != "issue-1" || rai["comment"] != "false positive: test fixture" {
		t.Errorf("unexpected reportedAlertInput: %v", rai)
	}
	if rai["exclusionMode"] != "fullScan" {
		t.Errorf("expected exclusionMode fullScan, got: %v", rai["exclusionMode"])
	}
}

func TestReportFalsePositivePipeline_UsesPipelineMutation(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := reportFalsePositivePipeline(context.Background(), nil, ReportFalsePositivePipelineInput{
		OxIssueID: "issue-2",
		Comment:   "pipeline fp",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %+v", res.Content)
	}
	if !strings.Contains(got.Query, "reportAlertAsFalsePositiveForPipelineIssues") {
		t.Errorf("expected pipeline false-positive mutation, got: %s", got.Query)
	}
}

func TestExcludeIssues_BuildsInput(t *testing.T) {
	var got capturedRequest
	ts := newFakeOX(t, &got)
	defer ts.Close()

	res, _, err := excludeIssues(context.Background(), nil, ExcludeIssuesInput{
		IssueIDs:  []string{"issue-1", "issue-2"},
		Comment:   "bulk exclude",
		ExpiredAt: "2026-12-31T00:00:00.000Z",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %+v", res.Content)
	}
	if !strings.Contains(got.Query, "excludeIssues") {
		t.Errorf("expected excludeIssues in query, got: %s", got.Query)
	}
	in := inputOf(t, &got)
	ids, ok := in["issueIds"].([]any)
	if !ok || len(ids) != 2 {
		t.Fatalf("expected 2 issueIds, got: %v", in["issueIds"])
	}
	if in["comment"] != "bulk exclude" || in["expiredAt"] != "2026-12-31T00:00:00.000Z" {
		t.Errorf("unexpected optional fields: %v", in)
	}
}

func TestExcludeIssues_EmptyList(t *testing.T) {
	t.Setenv("OX_API_TOKEN", "test-token")
	t.Setenv("OX_API_URL", "http://127.0.0.1:0")
	if err := client.Init(); err != nil {
		t.Fatalf("client init: %v", err)
	}
	res, _, err := excludeIssues(context.Background(), nil, ExcludeIssuesInput{IssueIDs: nil})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error for empty issue_ids")
	}
}
