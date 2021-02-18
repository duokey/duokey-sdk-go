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

// Client implements the base client request and response handling. All 
// services rely on this client.
type Client struct {
	Config duokey.Config
}

type duoKeyTransport struct {
	TenantID uint32
}

// RoundTrip adds the tenant ID to the PasswordCredentialsToken request.
// Remark: we shouln't mutate a request this way. However, it seems that it's the
// only solution to modify the header when calling PasswordCredentialsToken (see
// https://developer20.com/add-header-to-every-request-in-go/ and
// https://rakyll.medium.com/context-propagation-over-http-in-go-d4540996e9b0).
func (t *duoKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Abp.TenantId", fmt.Sprint(t.TenantID))
	return http.DefaultTransport.RoundTrip(req)
}

var _ http.RoundTripper = (*duoKeyTransport)(nil)

// New returns a pointer to a new DuoKey client. If the credentials are correct, we obtain a DuoKey access token.
// Then we configure an HTTP client using the token. The token will auto-refresh as necessary.
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

	ctx, cancel := context.WithTimeout(context.Background(), httpClientTimeout)
	defer cancel()

	clientConfig := duokey.Config{Credentials: creds,
		Routes:     routes,
		HTTPClient: oauth2Config.Client(ctx, token)}
	client := &Client{Config: clientConfig}

	return client, nil
}

// NewRequest returns a request pointer, The tenant ID is added to the http header.  
func (c *Client) NewRequest(operation *request.Operation, params interface{}, data interface{}) *request.Request {

	return request.New(c.Config, operation, params, data)
}
