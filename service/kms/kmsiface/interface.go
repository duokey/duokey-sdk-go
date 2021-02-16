package kmsiface

import (
	"github.com/duokey/duokey-sdk-go/service/kms"
)

// KMSAPI ...
type KMSAPI interface {
	Encrypt(*kms.EncryptInput) (*kms.EncryptOutput, error)
	Decrypt(*kms.DecryptInput) (*kms.DecryptOutput, error)
}

// Ensure that KMS implements the KMSAPI interface 
var _ KMSAPI = (*kms.KMS)(nil)
