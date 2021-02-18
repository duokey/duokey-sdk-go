package kmsiface

import (
	"github.com/duokey/duokey-sdk-go/service/kms"
)

// KMSAPI provides an interface to enable mocking the kms.KMS service 
// client's API calls. This makes unit testing easier. 
type KMSAPI interface {
	Encrypt(*kms.EncryptInput) (*kms.EncryptOutput, error)
	Decrypt(*kms.DecryptInput) (*kms.DecryptOutput, error)
}

// Ensure that KMS implements the KMSAPI interface 
var _ KMSAPI = (*kms.KMS)(nil)
