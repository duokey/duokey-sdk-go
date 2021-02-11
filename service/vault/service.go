package vault

import (
	"github.com/duokey/duokey-sdk-go/duokey/client"
	"github.com/duokey/duokey-sdk-go/duokey/request"
	"github.com/satori/go.uuid"
)

// Vault implements the VaultAPI interface
type Vault struct {
	*client.Client

	KeyID uuid.UUID
}

func (c *Vault) newRequest(op *request.Operation, params interface{}, data interface{}) *request.Request {
	req := c.NewRequest(op, params, data)

	return req
}