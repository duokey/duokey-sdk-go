package vault

import "context"

// SealRequest ...
type SealRequest struct {
	// KeyID
	// TenantID -> to be copied into the header
	
	Plaintext []byte `json:"plain"`
}

// SealResponse ...
type SealResponse struct {
	Ciphertext []byte `json:"cipher"`
}

// UnsealRequest ...
type UnsealRequest struct {
	Ciphertext []byte `json:"cipher"`
}

// UnsealResponse ...
type UnsealResponse struct {
	Plaintext []byte `json:"plain"`
}

// Seal ...
func (k *Vault) Seal(ctx context.Context, req *SealRequest) (*SealResponse, error) {
	return nil, nil

	// Send

	// Get the ciphertext
}

// Unseal ...
func (k *Vault) Unseal(ctx context.Context, req *UnsealRequest) (*UnsealResponse, error) {
	return nil, nil
}
