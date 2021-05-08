package kms

import (
	"github.com/duokey/duokey-sdk-go/duokey"
	"github.com/duokey/duokey-sdk-go/duokey/client"
	"github.com/duokey/duokey-sdk-go/duokey/credentials"
)

// KMS implements the KMSAPI interface
type KMS struct {
	*client.Client
	*Endpoints
}

// Endpoints of the crypto services (all routes of the DuoKey REST API
// are customizable)
type Endpoints struct {
	BaseURL      string
	EncryptRoute string
	DecryptRoute string
}

// New checks the credentials and returns a KMS client.
func New(credentials credentials.Config, endpoints Endpoints, logger duokey.Logger) (*KMS, error) {
	client, err := client.New(credentials, logger)
	if err != nil {
		return nil, err
	}
	
	return &KMS{Client: client, Endpoints: &endpoints}, nil
}
