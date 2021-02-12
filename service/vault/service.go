package vault

import (
	"github.com/duokey/duokey-sdk-go/duokey/client"
	"github.com/duokey/duokey-sdk-go/duokey/credentials"
	"github.com/duokey/duokey-sdk-go/duokey/request"
)

// Vault implements the VaultAPI interface
type Vault struct {
	*client.Client
}

// New ...
func New(credentials credentials.Config) (*Vault, error) {
	client, err := client.New(credentials)
	if err != nil {
		return nil, err
	}
	return &Vault{Client: client}, nil
}

func (c *Vault) newRequest(op *request.Operation, params interface{}, data interface{}) *request.Request {
	req := c.NewRequest(op, params, data)

	return req
}