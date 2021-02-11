package kms

import (
	"context"

	_ "github.com/duokey/duokey-sdk-go/duokey"
)

// List of supported encryption algorithms
const (
	AlgoAES string = "AES"
)

// List of supported cipher modes
const (
	CipherModeCBC string = "CBC"
	CipherModeGCM string = "GCM"
)

// EncryptRequest ...
type EncryptRequest struct {
	// KeyID
	// TenantID -> to be copied into the header
	
	Plaintext []byte `json:"plain"`
	Algorithm string `json:"algo"`
	CipherMode string `json:"mode,omitempty"`
	IV []byte `json:"iv,omitempty"`
}

// EncryptResponse ...
type EncryptResponse struct {
	Ciphertext []byte `json:"cipher"`
}

// DecryptRequest ...
type DecryptRequest struct {
	Ciphertext []byte `json:"cipher"`
	IV []byte `json:"iv,omitempty"`
}

// DecryptResponse ...
type DecryptResponse struct {
	Plaintext []byte `json:"plain"`
}

// Encrypt ...
func (k *KMS) Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error) {
	return nil, nil

	// Send

	// Get the ciphertext
}

// Decrypt ...
func (k *KMS) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error) {
	return nil, nil
}
