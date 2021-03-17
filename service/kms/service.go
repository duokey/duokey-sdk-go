package kms

import (
	"github.com/duokey/duokey-sdk-go/duokey/client"
	"github.com/duokey/duokey-sdk-go/duokey/credentials"
	"github.com/duokey/duokey-sdk-go/duokey/request"
)

// KMS implements the KMSAPI interface
type KMS struct {
	*client.Client
	*Endpoints
}

// Endpoints of the crypto services (all routes of the DuoKey REST API
// are customizable)
type Endpoints struct {
	BasePath     string
	EncryptRoute string
	DecryptRoute string
}

// New checks the credentials and returns a KMS client.
func New(credentials credentials.Config, endpoints Endpoints) (*KMS, error) {
	client, err := client.New(credentials)
	if err != nil {
		return nil, err
	}
	return &KMS{Client: client, Endpoints: &endpoints}, nil
}

func (c *KMS) newRequest(op *request.Operation, params interface{}, data interface{}) *request.Request {
	req := c.NewRequest(op, params, data)

	return req
}
