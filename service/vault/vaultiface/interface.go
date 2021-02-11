package vaultiface

import (
	"github.com/duokey/duokey-sdk-go/service/vault"
)

// VaultAPI ...
type VaultAPI interface {
	Seal(*vault.SealInput) (*vault.SealOutput, error)
	Unseal(*vault.UnsealInput) (*vault.UnsealOutput, error)
} 

// Ensure that Vault implements the VaultAPI interface
var _ VaultAPI = (*vault.Vault)(nil)
