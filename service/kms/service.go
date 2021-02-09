package kms

import (
	"github.com/duokey/duokey-kms-go/duokey/client"
)

// KMS implements the KMSAPI interface
type KMS struct {
	*client.Client
}
