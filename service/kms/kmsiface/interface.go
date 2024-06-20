package kmsiface

import (
	"context"

	"github.com/duokey/duokey-sdk-go/service/kms"
)

// KMSAPI provides an interface to enable mocking the kms.KMS service
// client's API calls. This makes unit testing easier.
type KMSAPI interface {
	Import(*kms.ImportInput) (*kms.ImportOutput, error)
	ImportWithContext(context.Context, *kms.ImportInput) (*kms.ImportOutput, error)
	Encrypt(*kms.EncryptInput) (*kms.EncryptOutput, error)
	EncryptWithContext(context.Context, *kms.EncryptInput) (*kms.EncryptOutput, error)
	Decrypt(*kms.DecryptInput) (*kms.DecryptOutput, error)
	DecryptWithContext(context.Context, *kms.DecryptInput) (*kms.DecryptOutput, error)
	CSRImport(*kms.CSRImportInput) (*kms.CSRImportOutput, error)
	CSRImportWithContext(context.Context, *kms.CSRImportInput) (*kms.CSRImportOutput, error)
	CSRStatus(*kms.CSRStatusInput) (*kms.CSRStatusOutput, error)
	CSRStatusWithContext(context.Context, *kms.CSRStatusInput) (*kms.CSRStatusOutput, error)
}

// Ensure that KMS implements the KMSAPI interface
var _ KMSAPI = (*kms.KMS)(nil)
