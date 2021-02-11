package client

import (
	"github.com/duokey/duokey-sdk-go/duokey"
	"github.com/duokey/duokey-sdk-go/duokey/request"
)

// Client ...
type Client struct {
	Config duokey.Config
}

// New will return a pointer to a new initialized service client.
//func New(cfg aws.Config, info metadata.ClientInfo, handlers request.Handlers, options ...func(*Client)) *Client {

// New returns a pointer to a new DuoKey client	
func New() *Client {
	return nil
}

// NewRequest ...
func (c *Client) NewRequest(operation *request.Operation, params interface{}, data interface{}) *request.Request {

	return request.New(c.Config, operation, params, data)
}
