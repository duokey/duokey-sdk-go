package vaultiface

import (
	"context"

	"github.com/duokey/duokey-sdk-go/service/vault"
)

// VaultAPI ...
type VaultAPI interface {
	Seal(context.Context, *vault.SealRequest) (*vault.SealResponse, error)
	Unseal(context.Context, *vault.UnsealRequest) (*vault.UnsealResponse, error)
} 

// Ensure that Vault implements the VaultAPI interface
var _ VaultAPI = (*vault.Vault)(nil)
