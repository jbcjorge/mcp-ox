package client

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	errors "github.com/jbcjorge/errors-library"
)

const (
	defaultAPIURL       = "https://api.cloud.ox.security/api/apollo-gateway"
	defaultHTTPTimeout  = 60 * time.Second
	maxResponseSize     = 5 * 1024 * 1024 // 5MB
	maxIdleConns        = 20
	maxIdleConnsPerHost = 10
)

// Sentinel errors.
var (
	ErrNoToken       = errors.New("no API token configured")
	ErrRequestFailed = errors.New("request failed: %s")
	ErrHTTPError     = errors.New("http error %s")
	ErrGraphQL       = errors.New("graphql error: %s")
	ErrMarshal       = errors.New("marshal error")
	ErrUnmarshal     = errors.New("unmarshal error")
)

// Client is a GraphQL client for the OX Security API.
type Client struct {
	apiURL     string
	apiToken   string
	httpClient *http.Client
}

// graphQLRequest represents a GraphQL query payload.
type graphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

// graphQLResponse represents a raw GraphQL response.
type graphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []graphQLError  `json:"errors,omitempty"`
}

// graphQLError represents a GraphQL error.
type graphQLError struct {
	Message string `json:"message"`
}

var singleton *Client

// Init creates the singleton OX API client from environment variables.
func Init() error {
	token := os.Getenv("OX_API_TOKEN")
	if token == "" {
		return ErrNoToken.Parse()
	}

	apiURL := os.Getenv("OX_API_URL")
	if apiURL == "" {
		apiURL = defaultAPIURL
	}

	singleton = &Client{
		apiURL:   apiURL,
		apiToken: token,
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        maxIdleConns,
				MaxIdleConnsPerHost: maxIdleConnsPerHost,
			},
			Timeout: defaultHTTPTimeout,
		},
	}

	slog.Debug("ox client initialized", "url", apiURL)
	return nil
}

// Get returns the singleton client. Panics if Init was not called.
func Get() *Client {
	if singleton == nil {
		panic("oxclient.Init() must be called before oxclient.Get()")
	}
	return singleton
}

// Execute sends a GraphQL query to the OX API and returns the raw JSON data.
func (c *Client) Execute(ctx context.Context, query string, variables map[string]any) (json.RawMessage, error) {
	reqBody := graphQLRequest{
		Query:     query,
		Variables: variables,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, ErrMarshal.Parse(errors.WithError(err))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, ErrRequestFailed.Parse(errors.WithParsedMessage(c.apiURL), errors.WithError(err))
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.apiToken)

	slog.Debug("executing graphql request", "url", c.apiURL)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, ErrRequestFailed.Parse(errors.WithParsedMessage(c.apiURL), errors.WithError(err))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, ErrRequestFailed.Parse(errors.WithParsedMessage("reading response"), errors.WithError(err))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, ErrHTTPError.Parse(errors.WithParsedMessage(resp.Status))
	}

	var gqlResp graphQLResponse
	if err := json.Unmarshal(respBody, &gqlResp); err != nil {
		return nil, ErrUnmarshal.Parse(errors.WithError(err))
	}

	if len(gqlResp.Errors) > 0 {
		msgs := make([]string, 0, len(gqlResp.Errors))
		for _, e := range gqlResp.Errors {
			msgs = append(msgs, e.Message)
		}
		return nil, ErrGraphQL.Parse(errors.WithParsedMessage(strings.Join(msgs, "; ")))
	}

	return gqlResp.Data, nil
}
