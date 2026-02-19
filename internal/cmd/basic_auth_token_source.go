/*
Copyright (c) 2025 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/osac-project/fulfillment-common/auth"
)

// BasicAuthTokenSourceBuilder is a builder for creating a BasicAuthTokenSource.
type BasicAuthTokenSourceBuilder struct {
	logger       *slog.Logger
	tokenURL     string
	clientId     string
	clientSecret string
	scopes       []string
	caPool       *x509.CertPool
}

// NewBasicAuthTokenSource creates a new builder for BasicAuthTokenSource.
func NewBasicAuthTokenSource() *BasicAuthTokenSourceBuilder {
	return &BasicAuthTokenSourceBuilder{}
}

// SetLogger sets the logger.
func (b *BasicAuthTokenSourceBuilder) SetLogger(value *slog.Logger) *BasicAuthTokenSourceBuilder {
	b.logger = value
	return b
}

// SetTokenURL sets the token endpoint URL.
func (b *BasicAuthTokenSourceBuilder) SetTokenURL(value string) *BasicAuthTokenSourceBuilder {
	b.tokenURL = value
	return b
}

// SetClientId sets the client identifier.
func (b *BasicAuthTokenSourceBuilder) SetClientId(value string) *BasicAuthTokenSourceBuilder {
	b.clientId = value
	return b
}

// SetClientSecret sets the client secret.
func (b *BasicAuthTokenSourceBuilder) SetClientSecret(value string) *BasicAuthTokenSourceBuilder {
	b.clientSecret = value
	return b
}

// SetScopes sets the scopes to request.
func (b *BasicAuthTokenSourceBuilder) SetScopes(value ...string) *BasicAuthTokenSourceBuilder {
	b.scopes = value
	return b
}

// SetCaPool sets the CA certificate pool for TLS.
func (b *BasicAuthTokenSourceBuilder) SetCaPool(value *x509.CertPool) *BasicAuthTokenSourceBuilder {
	b.caPool = value
	return b
}

// Build creates the BasicAuthTokenSource.
func (b *BasicAuthTokenSourceBuilder) Build() (*BasicAuthTokenSource, error) {
	if b.logger == nil {
		return nil, errors.New("logger is mandatory")
	}
	if b.tokenURL == "" {
		return nil, errors.New("token URL is mandatory")
	}
	if b.clientId == "" {
		return nil, errors.New("client ID is mandatory")
	}
	if b.clientSecret == "" {
		return nil, errors.New("client secret is mandatory")
	}

	// Create HTTP client with TLS configuration.
	// If no CA pool is provided, use nil which means Go will use the system CA pool.
	// If a CA pool is provided, we still want to include system CAs for public endpoints.
	var rootCAs *x509.CertPool
	if b.caPool != nil {
		rootCAs = b.caPool
	}
	// Note: If rootCAs is nil, Go's TLS will use the system certificate pool,
	// which is what we want for public NVIDIA endpoints.

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: rootCAs,
		},
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return &BasicAuthTokenSource{
		logger:       b.logger,
		tokenURL:     b.tokenURL,
		clientId:     b.clientId,
		clientSecret: b.clientSecret,
		scopes:       b.scopes,
		httpClient:   httpClient,
	}, nil
}

// BasicAuthTokenSource is a token source that uses HTTP Basic Auth for the client credentials flow.
type BasicAuthTokenSource struct {
	logger       *slog.Logger
	tokenURL     string
	clientId     string
	clientSecret string
	scopes       []string
	httpClient   *http.Client

	// Cached token and mutex for thread safety
	mu          sync.Mutex
	cachedToken *auth.Token
}

// tokenResponse represents the OAuth token response.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Token returns a valid token, fetching a new one if necessary.
func (s *BasicAuthTokenSource) Token(ctx context.Context) (*auth.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if we have a cached token that's still valid (with 30 second buffer)
	if s.cachedToken != nil && time.Until(s.cachedToken.Expiry) > 30*time.Second {
		s.logger.DebugContext(ctx, "Using cached token",
			slog.Time("expiry", s.cachedToken.Expiry),
		)
		return s.cachedToken, nil
	}

	// Fetch a new token
	s.logger.InfoContext(ctx, "Fetching new token using Basic Auth",
		slog.String("token_url", s.tokenURL),
	)

	token, err := s.fetchToken(ctx)
	if err != nil {
		return nil, err
	}

	s.cachedToken = token
	return token, nil
}

// fetchToken performs the actual token request using Basic Auth.
func (s *BasicAuthTokenSource) fetchToken(ctx context.Context) (*auth.Token, error) {
	// Prepare form data
	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	if len(s.scopes) > 0 {
		formData.Set("scope", strings.Join(s.scopes, " "))
	}

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	// Set headers - use Basic Auth for credentials
	req.SetBasicAuth(s.clientId, s.clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	s.logger.DebugContext(ctx, "Sending token request",
		slog.String("url", s.tokenURL),
		slog.String("grant_type", "client_credentials"),
	)

	// Send the request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send token request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status %d", resp.StatusCode)
	}

	// Parse the response
	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	// Calculate expiry time
	expiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	s.logger.InfoContext(ctx, "Successfully obtained token",
		slog.Time("expiry", expiry),
		slog.Int("expires_in", tokenResp.ExpiresIn),
	)

	return &auth.Token{
		Access:  tokenResp.AccessToken,
		Refresh: tokenResp.RefreshToken,
		Expiry:  expiry,
	}, nil
}
