package kmsiface

import (
	"context"

	"github.com/duokey/duokey-sdk-go/service/kms"
)

// KMSAPI ...
type KMSAPI interface {
	Encrypt(context.Context, *kms.EncryptRequest) (*kms.EncryptResponse, error)
	Decrypt(context.Context, *kms.DecryptRequest) (*kms.DecryptResponse, error)
}

// Ensure that KMS is implementing the KMSAPI interface
var _ KMSAPI = (*kms.KMS)(nil)
