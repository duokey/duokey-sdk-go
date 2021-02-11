package client

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/duokey/duokey-sdk-go/duokey"
	"github.com/duokey/duokey-sdk-go/duokey/credentials"
	"github.com/duokey/duokey-sdk-go/duokey/request"
	"golang.org/x/oauth2"
)

// Client ...
type Client struct {
	Config duokey.Config
}

// New will return a pointer to a new initialized service client.
//func New(cfg aws.Config, info metadata.ClientInfo, handlers request.Handlers, options ...func(*Client)) *Client {

// New returns a pointer to a new DuoKey client	
func New(config duokey.Config) (*Client, error) {

	conf, err := credentials.GetOauth2Config(config)
	if err != nil {
		return nil, err
	}

	transport := &credentials.DuoKeyTransport{TenantID: config.TenantID}

	// The custom transport adds the tenant ID to the header
	httpClient := &http.Client{Transport: transport, Timeout: time.Second * 20}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)

	// Password credentials call
	token, err := conf.PasswordCredentialsToken(ctx, "admin", "123qwe")
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

	return nil, nil
}

// NewRequest ...
func (c *Client) NewRequest(operation *request.Operation, params interface{}, data interface{}) *request.Request {

	return request.New(c.Config, operation, params, data)
}
