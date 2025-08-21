package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/duokey/duokey-sdk-go/duokey"
	"github.com/duokey/duokey-sdk-go/duokey/credentials"
	"github.com/duokey/duokey-sdk-go/duokey/request"
	"golang.org/x/oauth2"
)

const (
	context_api_id    string = "appid"
	context_tenant_id string = "tenantid"
)

// Client implements the base client request and response handling. All
// services rely on this client.
type Client struct {
	Config duokey.Config
}

// Wrap http.RoundTripper to log HTTP requests
type transportWithLogger struct {
	Transport http.RoundTripper
	Logger    duokey.Logger
}

// Ensure that transportWithLogger implements the http.RoundTripper interface
var _ http.RoundTripper = (*transportWithLogger)(nil)

func (twl *transportWithLogger) RoundTrip(req *http.Request) (*http.Response, error) {

	// Start the timer and log the event
	start := time.Now()
	msg := fmt.Sprintf("request to %v", req.URL)
	defer duokey.LogExecutionTime(twl.Logger, msg, start)

	// Send the request
	return twl.Transport.RoundTrip(req)
}

type duoKeyTransport struct {
	TenantID       uint32
	HeaderTenantID string
	Logger         duokey.Logger
}

var _ http.RoundTripper = (*duoKeyTransport)(nil)

// RoundTrip adds the tenant ID to the PasswordCredentialsToken request.
// Remark: we shouln't mutate a request this way. However, it seems that it's the
// only solution to modify the header when calling PasswordCredentialsToken (see
// https://developer20.com/add-header-to-every-request-in-go/ and
// https://rakyll.medium.com/context-propagation-over-http-in-go-d4540996e9b0).
func (t *duoKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set(t.HeaderTenantID, fmt.Sprint(t.TenantID))
	start := time.Now()
	msg := fmt.Sprintf("request to %v", req.URL)
	defer duokey.LogExecutionTime(t.Logger, msg, start)

	return http.DefaultTransport.RoundTrip(req)
}

// New returns a pointer to a new DuoKey client.
// If the credentials are correct, we obtain a DuoKey access token.
// We configure an HTTP client using the token.
// The token is tested/renewed when it expires (see the comment of client.checkToken())
//
//	client.checkToken() is currently called each time a new request is prepared ((c *Client) NewRequest)
//
// checkTokenTimeOut: The timeout in seconds for the cockpit call to get/check the token
func New(creds credentials.Config, logger duokey.Logger, checkTokenTimeOut int) (*Client, error) {

	var clientConfig duokey.Config

	// Logger
	if logger == nil {
		clientConfig.Logger = duokey.NewDefaultLogger()
	} else {
		clientConfig.Logger = logger
	}

	// Read the discovery document
	oauth2Config, err := credentials.GetOauth2Config(creds)
	if err != nil {
		clientConfig.Logger.Warnf("could not read the token and authorization URLs from the discovery document: %v", err)
		return nil, err
	}

	// Remark: the token is requested and set in the Transport later in this function by calling client.checkToken()

	// Prepare the wrapper for the oauth2Client.Transport to log all requests
	transportWithLogger := &transportWithLogger{
		//Transport: oauth2Client.Transport, // will be set here under by client.checkToken()
		Logger: clientConfig.Logger,
	}

	// Configure the new DuoKey client
	// clientConfig.Token will be set here under by client.checkToken()
	clientConfig.Credentials = creds
	clientConfig.OAuth2Config = oauth2Config
	clientConfig.HTTPClient = &http.Client{
		Transport: transportWithLogger,
	}

	clientConfig.CheckTokenTimeOut = time.Duration(checkTokenTimeOut) * time.Second

	client := &Client{Config: clientConfig}

	// Prepare the first token for the client
	client.checkToken()

	return client, nil
}

// NewRequest returns a request pointer. The tenant ID is added to the HTTP header.
func (c *Client) NewRequest(operation *request.Operation, params interface{}, data interface{}) *request.Request {

	// Renew the token if necessary
	// if an error occurs, nothing is done currently, the Cockpit call will fail
	c.checkToken()

	return request.New(c.Config, operation, params, data)

}

// send a request, and if 401 update the token and send once again
// To send the request a second time, it must be cloned
// The result will be stored in the req.Response (also referenced in 'out' variable by the caller)
func (c *Client) SendRequestWithTokenUpdate(req *request.Request) error {
	err := req.Send()

	if err == nil {
		return nil
	}

	// Check if error 401, currently having to check for that string
	// that is set in request.go parseHTTPResponse()
	if strings.Contains(err.Error(), "request failed with status 401:") {
		c.Config.Logger.Info("SendRequestWithTokenUpdate() 401 - renew Token and clone request to resend")
		// renew the token and retry

		err = c.renewToken()
		if err != nil {
			return err
		}

		clonedReq, err := req.CloneRequest(&c.Config)
		if err != nil {
			return err
		}

		return clonedReq.Send()
	} else { // the error is not a token renewal problem, return it
		return err
	}

}

// GetMandatoryContext returns a map storing the context required by the DuoKey server for some of the calls (encryptRequest, decryptRequest, etc.)
func (c *Client) GetMandatoryContext() map[string]string {
	context := make(map[string]string)

	context[context_api_id] = c.Config.Credentials.AppID
	context[context_tenant_id] = strconv.Itoa(int(c.Config.Credentials.TenantID))

	return context
}

// checkToken make sure that the client and its transport have a valid token
// If no token is present (it is the case when first creating the client)
//
//	or if the token has expired, then a new token is requested
//
// This conforms to the spec:
//
//	For machine-to-machine (M2M) communication where microservices access protected APIs, the Client Credentials Grant is the preferred method:
//	When the Access Token expires, the microservice simply requests a new token using the same client credentials, without the need for a refresh token.
func (c *Client) checkToken() error {
	c.Config.Logger.Debug("checkToken() - checking the current token")
	renew := false

	if c.Config.OAuth2Config == nil {
		c.Config.Logger.Warn("checkToken() failed: c.Config.OAuth2Config == nil")
		return errors.New("checkToken() failed: c.Config.OAuth2Config == nil")
	}

	if c.Config.Token != nil {
		// Token validation
		renew = !c.Config.Token.Valid()
	} else { // no token yet
		renew = true
		c.Config.Logger.Debug("checkToken() - No token present")
	}

	if renew {
		return c.renewToken()
	} else {
		c.Config.Logger.Debug("checkToken() - Token is still valid")
	}

	return nil
}

func (c *Client) renewToken() error {
	c.Config.Logger.Debug("renewToken() - A new token is requested")
	// The custom transport adds the tenant ID to the header
	transport := &duoKeyTransport{
		TenantID:       c.Config.Credentials.TenantID,
		HeaderTenantID: c.Config.Credentials.HeaderTenantID,
		Logger:         c.Config.Logger,
	}

	httpClient := &http.Client{Transport: transport, Timeout: c.Config.CheckTokenTimeOut}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)

	var token *oauth2.Token
	var err error
	// Password credentials call
	token, err = c.Config.OAuth2Config.PasswordCredentialsToken(ctx, c.Config.Credentials.UserName, c.Config.Credentials.Password)
	if err != nil {
		c.Config.Logger.Warnf("renewToken() - could not get the token: %v", err)
		return err
	}

	// Token validation
	if !token.Valid() {
		c.Config.Logger.Warnf("renewToken() - the new token is invalid")
		return errors.New("renewToken() - the new token is invalid")
	}

	if token.TokenType != "Bearer" {
		c.Config.Logger.Warnf("renewToken() - bad token: expected 'Bearer', got '%s'", token.TokenType)
		return errors.New("renewToken() - bad token: expected 'Bearer', got " + token.TokenType)
	}

	// Get an OAuth 2 client
	oauth2Client := c.Config.OAuth2Config.Client(context.Background(), token)

	// save the new token and Transport
	c.Config.Token = token // store the token to check its validity before each call and manage expiration
	c.Config.HTTPClient.Transport = oauth2Client.Transport
	c.Config.Logger.Debug("renewToken() - Token renewed")

	return nil
}

// AuthenticateUser
// Code similar to checkToken(), but just to validate that a user/pwd is valid for the cockpit
// Validation is done by requesting a token, which is returned
func (c *Client) AuthenticateUser(UserName string, Password string) (*oauth2.Token, error) {
	if c.Config.OAuth2Config == nil {
		c.Config.Logger.Warn("AuthenticateUser() failed: c.Config.OAuth2Config == nil")
		return nil, errors.New("AuthenticateUser() failed: c.Config.OAuth2Config == nil")
	}

	c.Config.Logger.Debug("AuthenticateUser() - Requesting a token")
	// The custom transport adds the tenant ID to the header
	transport := &duoKeyTransport{
		TenantID:       c.Config.Credentials.TenantID,
		HeaderTenantID: c.Config.Credentials.HeaderTenantID,
		Logger:         c.Config.Logger,
	}

	httpClient := &http.Client{Transport: transport, Timeout: c.Config.CheckTokenTimeOut}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient) // c.Config.HTTPClient

	// Password credentials call
	token, err := c.Config.OAuth2Config.PasswordCredentialsToken(ctx, UserName, Password)
	if err != nil {
		c.Config.Logger.Warnf("AuthenticateUser() - could not get the token: %v", err)
		return nil, err
	}

	// Token validation
	if !token.Valid() {
		c.Config.Logger.Warnf("AuthenticateUser() - the new token is invalid")
		return nil, errors.New("AuthenticateUser() - the new token is invalid")
	}

	if token.TokenType != "Bearer" {
		c.Config.Logger.Warnf("AuthenticateUser() - bad token: expected 'Bearer', got '%s'", token.TokenType)
		return nil, errors.New("AuthenticateUser() - bad token: expected 'Bearer', got " + token.TokenType)
	}

	return token, nil
}
