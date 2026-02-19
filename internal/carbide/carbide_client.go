/*
Copyright (c) 2025 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package carbide

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/osac-project/fulfillment-common/auth"
)

// ClientBuilder contains the data and logic needed to create a client for the Carbide API.
type ClientBuilder struct {
	logger      *slog.Logger
	caPool      *x509.CertPool
	userAgent   string
	url         string
	org         string
	tokenSource auth.TokenSource
}

// Client is a client for the Carbide API.
type Client struct {
	logger      *slog.Logger
	userAgent   string
	url         string
	org         string
	tokenSource auth.TokenSource
	client      *http.Client
}

// NewClient creates a builder that can then be used to create a new client for the Carbide API.
func NewClient() *ClientBuilder {
	return &ClientBuilder{}
}

// SetLogger sets the logger that the client will use to write messages to the log. This is mandatory.
func (b *ClientBuilder) SetLogger(value *slog.Logger) *ClientBuilder {
	b.logger = value
	return b
}

// SetCaPool sets the CA pool that the client will use to verify the server's certificate. This is optional.
func (b *ClientBuilder) SetCaPool(value *x509.CertPool) *ClientBuilder {
	b.caPool = value
	return b
}

// SetUserAgent sets the user agent that the client will use to identify itself. This is optional.
func (b *ClientBuilder) SetUserAgent(value string) *ClientBuilder {
	b.userAgent = value
	return b
}

// SetUrl sets the base URL of the Carbide API. This is mandatory.
func (b *ClientBuilder) SetUrl(value string) *ClientBuilder {
	b.url = value
	return b
}

// SetOrg sets the organization. This is mandatory.
func (b *ClientBuilder) SetOrg(value string) *ClientBuilder {
	b.org = value
	return b
}

// SetTokenSource sets the token source that the client will use to authenticate requests. This is mandatory.
func (b *ClientBuilder) SetTokenSource(value auth.TokenSource) *ClientBuilder {
	b.tokenSource = value
	return b
}

// Build uses the information stored in the builder to create a new client for the Carbide API.
func (b *ClientBuilder) Build() (result *Client, err error) {
	// Check parameters:
	if b.logger == nil {
		return nil, errors.New("logger is mandatory")
	}
	if b.url == "" {
		return nil, errors.New("base URL is mandatory")
	}
	if b.org == "" {
		return nil, errors.New("organization is mandatory")
	}
	if b.tokenSource == nil {
		return nil, errors.New("token source is mandatory")
	}

	// Create the HTTP client:
	var transport http.RoundTripper = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: b.caPool,
		},
	}
	client := &http.Client{
		Transport: transport,
	}

	// Create and populate the object:
	result = &Client{
		logger:      b.logger,
		userAgent:   b.userAgent,
		url:         b.url,
		org:         b.org,
		tokenSource: b.tokenSource,
		client:      client,
	}
	return
}

// Get creates a new GET request.
func (c *Client) Get() *Request {
	return &Request{
		method: http.MethodGet,
		client: c,
	}
}

// Post creates a new POST request.
func (c *Client) Post() *Request {
	return &Request{
		method: http.MethodPost,
		client: c,
	}
}

type Request struct {
	client   *Client
	method   string
	endpoint string
	query    url.Values
	input    any
	output   any
}

func (r *Request) SetEndpoint(segments ...string) *Request {
	r.endpoint = strings.Join(segments, "/")
	return r
}

func (r *Request) SetQueryParameter(name string, value any) *Request {
	if r.query == nil {
		r.query = url.Values{}
	}
	r.query.Set(name, fmt.Sprintf("%v", value))
	return r
}

func (r *Request) SetInput(value any) *Request {
	r.input = value
	return r
}

func (r *Request) SetOutput(value any) *Request {
	r.output = value
	return r
}

// Send sends the request to the Carbide API and deserializes the response.
func (r *Request) Send(ctx context.Context) error {
	// Calculate the URL:
	requestUrl := fmt.Sprintf("%s/v2/org/%s/forge/%s", r.client.url, r.client.org, r.endpoint)
	if len(r.query) > 0 {
		requestUrl = fmt.Sprintf("%s?%s", requestUrl, r.query.Encode())
	}

	// Serialize the request body:
	var requestBody io.Reader
	if r.input != nil {
		requestData, err := json.Marshal(r.input)
		if err != nil {
			return fmt.Errorf("failed to serialize input: %w", err)
		}
		requestBody = bytes.NewReader(requestData)
	}

	// Create the HTTP request:
	httpRequest, err := http.NewRequestWithContext(ctx, r.method, requestUrl, requestBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpHeader := httpRequest.Header
	httpHeader.Set("User-Agent", userAgent)
	httpHeader.Set("Content-Type", "application/json")
	httpHeader.Set("Accept", "application/json")
	if r.client.tokenSource != nil {
		token, err := r.client.tokenSource.Token(ctx)
		if err != nil {
			return fmt.Errorf("failed to get token: %w", err)
		}
		httpRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.Access))
	}

	// Log the request:
	r.client.logger.DebugContext(
		ctx,
		"Sending request",
		slog.String("url", requestUrl),
		slog.String("method", r.method),
		slog.Any("input", r.input),
	)

	// Send the HTTP request:
	httpResponse, err := r.client.client.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer httpResponse.Body.Close()

	// Get the response data:
	responseData, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Log the response:
	r.client.logger.DebugContext(
		ctx,
		"Received response",
		slog.Int("status", httpResponse.StatusCode),
		slog.String("response", string(responseData)),
	)

	// Deserialize the response body:
	if r.output != nil {
		err = json.Unmarshal(responseData, r.output)
		if err != nil {
			return fmt.Errorf("failed to deserialize response body: %w", err)
		}
	}

	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		return fmt.Errorf(
			"request to '%s' returned unexpected status code %d: %s",
			r.endpoint, httpResponse.StatusCode, string(responseData),
		)
	}

	return nil
}

// userAgent is the user agent string for the carbide client.
const userAgent = "carbide-client"
