package kms

import (
	"context"

	"github.com/duokey/duokey-sdk-go/duokey"
)

// EncryptRequest ...
type EncryptRequest struct {
	Plaintext duokey.Blob
}

// EncryptResponse ...
type EncryptResponse struct {
	Ciphertext duokey.Blob
}

// DecryptRequest ...
type DecryptRequest struct {
	Ciphertext duokey.Blob
}

// DecryptResponse ...
type DecryptResponse struct {
	Plaintext duokey.Blob
}

// Encrypt ...
func (k *KMS) Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error) {
	return nil, nil
} 

// Decrypt ...
func (k *KMS) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error) {
	return nil, nil
} 