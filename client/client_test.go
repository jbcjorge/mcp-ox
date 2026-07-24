package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	errors "github.com/jbcjorge/errors-library"
)

func resetSingleton() {
	singleton = nil
}

func TestInit_NoToken(t *testing.T) {
	resetSingleton()
	t.Setenv("OX_API_TOKEN", "")
	err := Init()
	if !errors.Is(err, ErrNoToken) {
		t.Fatalf("expected ErrNoToken, got: %v", err)
	}
}

func TestInit_Success(t *testing.T) {
	resetSingleton()
	t.Setenv("OX_API_TOKEN", "test-token")
	t.Setenv("OX_API_URL", "http://localhost:9999")
	if err := Init(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if Get() == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestExecute_Success(t *testing.T) {
	resetSingleton()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"test": "value"},
		})
	}))
	defer ts.Close()

	t.Setenv("OX_API_TOKEN", "test-token")
	t.Setenv("OX_API_URL", ts.URL)
	if err := Init(); err != nil {
		t.Fatalf("init error: %v", err)
	}

	data, err := Get().Execute(context.Background(), "{ test }", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data == nil {
		t.Fatal("expected non-nil data")
	}
}

func TestExecute_HTTPError(t *testing.T) {
	resetSingleton()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer ts.Close()

	t.Setenv("OX_API_TOKEN", "test-token")
	t.Setenv("OX_API_URL", ts.URL)
	if err := Init(); err != nil {
		t.Fatalf("init error: %v", err)
	}

	_, err := Get().Execute(context.Background(), "{ test }", nil)
	if !errors.Is(err, ErrHTTPError) {
		t.Fatalf("expected ErrHTTPError, got: %v", err)
	}
}

func TestExecute_GraphQLError(t *testing.T) {
	resetSingleton()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"errors": []map[string]any{{"message": "field not found"}},
		})
	}))
	defer ts.Close()

	t.Setenv("OX_API_TOKEN", "test-token")
	t.Setenv("OX_API_URL", ts.URL)
	if err := Init(); err != nil {
		t.Fatalf("init error: %v", err)
	}

	_, err := Get().Execute(context.Background(), "{ test }", nil)
	if !errors.Is(err, ErrGraphQL) {
		t.Fatalf("expected ErrGraphQL, got: %v", err)
	}
}
