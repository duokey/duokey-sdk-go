package kms

import (
	"github.com/duokey/duokey-sdk-go/duokey/client"
)

// KMS implements the KMSAPI interface
type KMS struct {
	*client.Client
}
