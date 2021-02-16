package kms

import (
	"github.com/duokey/duokey-sdk-go/duokey/client"
	"github.com/duokey/duokey-sdk-go/duokey/credentials"
	"github.com/duokey/duokey-sdk-go/duokey/request"
	"github.com/duokey/duokey-sdk-go/duokey/restapi"
)

// KMS implements the KMSAPI interface
type KMS struct {
	*client.Client
}

// New ...
func New(credentials credentials.Config, routes restapi.Config) (*KMS, error) {
	client, err := client.New(credentials, routes)
	if err != nil {
		return nil, err
	}
	return &KMS{Client: client}, nil
}

func (c *KMS) newRequest(op *request.Operation, params interface{}, data interface{}) *request.Request {
	req := c.NewRequest(op, params, data)

	return req
}
