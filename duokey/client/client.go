package client

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/duokey/duokey-sdk-go/duokey"
	"github.com/duokey/duokey-sdk-go/duokey/credentials"
	"github.com/duokey/duokey-sdk-go/duokey/request"
	"github.com/duokey/duokey-sdk-go/duokey/restapi"
	"golang.org/x/oauth2"
)

const (
	httpClientTimeout time.Duration = time.Second * 10
)

// Client ...
type Client struct {
	Config duokey.Config
}

type duoKeyTransport struct {
	TenantID uint32
}

// RoundTrip adds the tenant ID to the PasswordCredentialsToken request.
// Remark: we shouln't mutate a request this way. However the context of 
// PasswordCredentialsToken controls only which HTTP client is used
// (see https://github.com/golang/oauth2/blob/66670185b0cdf83286f736c2e4cdced4d9cb6170/internal/transport.go#L23) 
func (t *duoKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Abp.TenantId", fmt.Sprint(t.TenantID))
	return http.DefaultTransport.RoundTrip(req)
}

var _ http.RoundTripper = (*duoKeyTransport)(nil)

// New returns a pointer to a new DuoKey client
func New(creds credentials.Config, routes restapi.Config) (*Client, error) {

	oauth2Config, err := credentials.GetOauth2Config(creds)
	if err != nil {
		return nil, err
	}

	// The custom transport adds the tenant ID to the header
	transport := &duoKeyTransport{TenantID: creds.TenantID}

	httpClient := &http.Client{Transport: transport, Timeout: httpClientTimeout}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)

	// Password credentials call
	token, err := oauth2Config.PasswordCredentialsToken(ctx, creds.UserName, creds.Password)
	if err != nil {
		return nil, err
	}

	// Token validation
	if !token.Valid() {
		return nil, fmt.Errorf("Failed to check the token")
	}

	if token.TokenType != "Bearer" {
		return nil, fmt.Errorf("bad token: expected 'Bearer', got '%s'", token.TokenType)
	}

	// fmt.Println("Refresh token:")
	// fmt.Println(token.Expiry.String())
	// fmt.Println(token.AccessToken)

	// token.AccessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjYwM0ExQUZEN0QwRUU0RDAzNzc3NDJGMTgwODI0RjAyIiwidHlwIjoiYXQrand0In0.eyJuYmYiOjE2MTMxMjcwMzQsImV4cCI6MTYxMzEzMDYzNCwiaXNzIjoiaHR0cHM6Ly9kdW9rZXktY29ja3BpdC5henVyZXdlYnNpdGVzLm5ldCIsImF1ZCI6ImRlZmF1bHQtYXBpIiwiY2xpZW50X2lkIjoiZGtlLmNvY2twaXQiLCJzdWIiOiIyIiwiYXV0aF90aW1lIjoxNjEzMTI3MDM0LCJpZHAiOiJsb2NhbCIsImh0dHA6Ly93d3cuYXNwbmV0Ym9pbGVycGxhdGUuY29tL2lkZW50aXR5L2NsYWltcy90ZW5hbnRJZCI6IjEiLCJqdGkiOiIwRDNGNTE4NDgzQkI2NEU2NzY2NjNFRTdBNDg0MUJDQyIsImlhdCI6MTYxMzEyNzAzNCwic2NvcGUiOlsiZGVmYXVsdC1hcGkiXSwiYW1yIjpbInB3ZCJdfQ.tjTuOMAWxpTfDYy52ebF8gLhw2huTDvfVVFJ6hiiRH5321Zmro9gOfsc0APCw9kjikgv7c8NFcJpkMsjesIF8xjuIv0ss-3jpo-PY05cMk9ZnxVLGtBvZ4-rVwyKOGe3TB_PENLxHgw1mueRkUCXZ-ny1tUqHA6cRDzV193LlTWSlSZ3VAJEURyK-_QgGv4e5dgjHs7xQ9--qMSn6oPnlAbhS-9hzqCX8WYttfuG-NkN61waPhhUzHDai2iCapTXKpWbjQ59gfmU9VMXnTNJVLO_kaYIDN00oD-Ooo4-gR5t0_LFRlmBiH4pEgEOZ_f13EWJSatcQ3Qt_rKCvgiMtA"

	ctx, cancel := context.WithTimeout(context.Background(), httpClientTimeout)
	defer cancel()

	clientConfig := duokey.Config{Credentials: creds,
		Routes:     routes,
		HTTPClient: oauth2Config.Client(ctx, token)}
	client := &Client{Config: clientConfig}

	return client, nil
}

// NewRequest ...
func (c *Client) NewRequest(operation *request.Operation, params interface{}, data interface{}) *request.Request {

	return request.New(c.Config, operation, params, data)
}

// eyJhbGciOiJSUzI1NiIsImtpZCI6IjYwM0ExQUZEN0QwRUU0RDAzNzc3NDJGMTgwODI0RjAyIiwidHlwIjoiYXQrand0In0.eyJuYmYiOjE2MTMxMjcwMzQsImV4cCI6MTYxMzEzMDYzNCwiaXNzIjoiaHR0cHM6Ly9kdW9rZXktY29ja3BpdC5henVyZXdlYnNpdGVzLm5ldCIsImF1ZCI6ImRlZmF1bHQtYXBpIiwiY2xpZW50X2lkIjoiZGtlLmNvY2twaXQiLCJzdWIiOiIyIiwiYXV0aF90aW1lIjoxNjEzMTI3MDM0LCJpZHAiOiJsb2NhbCIsImh0dHA6Ly93d3cuYXNwbmV0Ym9pbGVycGxhdGUuY29tL2lkZW50aXR5L2NsYWltcy90ZW5hbnRJZCI6IjEiLCJqdGkiOiIwRDNGNTE4NDgzQkI2NEU2NzY2NjNFRTdBNDg0MUJDQyIsImlhdCI6MTYxMzEyNzAzNCwic2NvcGUiOlsiZGVmYXVsdC1hcGkiXSwiYW1yIjpbInB3ZCJdfQ.tjTuOMAWxpTfDYy52ebF8gLhw2huTDvfVVFJ6hiiRH5321Zmro9gOfsc0APCw9kjikgv7c8NFcJpkMsjesIF8xjuIv0ss-3jpo-PY05cMk9ZnxVLGtBvZ4-rVwyKOGe3TB_PENLxHgw1mueRkUCXZ-ny1tUqHA6cRDzV193LlTWSlSZ3VAJEURyK-_QgGv4e5dgjHs7xQ9--qMSn6oPnlAbhS-9hzqCX8WYttfuG-NkN61waPhhUzHDai2iCapTXKpWbjQ59gfmU9VMXnTNJVLO_kaYIDN00oD-Ooo4-gR5t0_LFRlmBiH4pEgEOZ_f13EWJSatcQ3Qt_rKCvgiMtA
