package kms

import (
	"context"
	"fmt"
	"net/http"

	"github.com/duokey/duokey-sdk-go/duokey/request"
)

// Encryption
const opEncrypt = "Encrypt"

// EncryptInput contains a payload to be encrypted by DuoKey. DuoKey determines the encryption
// algorithm from the VaultID and KeyId. The optional field Algorithm allows you to specify a
// chaining mode or a padding scheme. An initial vector or a tag can be supplied using the
// Context field.
type EncryptInput struct {
	ID        uint32            `json:"id"`
	KeyID     string            `json:"keyid"`
	VaultID   string            `json:"vaultid"`
	Algorithm string            `json:"algorithm,omitempty"`
	Context   map[string]string `json:"context,omitempty"`
	Payload   []byte            `json:"payload"`
}

// EncryptOutput contains the deserialized payload returned by the DuoKey server.
type EncryptOutput struct {
	Success bool `json:"success"`
	Result  struct {
		KeyID     string `json:"keyid"`
		Algorithm string `json:"algorithm"`
		Payload   []byte `json:"payload"`
		ID        uint32 `json:"id"`
	} `json:"result"`
	TargetURL           *string `json:"targetUrl"`
	Error               *string `json:"error"`
	UnauthorizedRequest bool    `json:"unAuthorizedRequest"`
	ABP                 bool    `json:"__abp"`
}

func validateEncryptInput(input *EncryptInput) error {
	if input.KeyID == "" {
		return fmt.Errorf("The key ID cannot be an empty string")
	}

	if input.VaultID == "" {
		return fmt.Errorf("The vault ID cannot be an empty string")
	}

	return nil
}

// Encrypt API operation for DuoKey
func (k *KMS) Encrypt(input *EncryptInput) (*EncryptOutput, error) {
	
	if err := validateEncryptInput(input); err != nil {
		return nil, err
	}

	req, out := k.encryptRequest(input)

	return out, req.Send()
}

// EncryptWithContext is the same operation as Encrypt. It is however possible
// to pass a non-nil context.
func (k *KMS) EncryptWithContext(ctx context.Context, input *EncryptInput) (*EncryptOutput, error) {

	if err := validateEncryptInput(input); err != nil {
		return nil, err
	}

	req, out := k.encryptRequest(input)
	req.SetContext(ctx)

	return out, req.Send()
}

func (k *KMS) encryptRequest(input *EncryptInput) (req *request.Request, output *EncryptOutput) {

	op := &request.Operation{
		Name:       opEncrypt,
		HTTPMethod: http.MethodPost,
		BaseURL:    k.Endpoints.BaseURL,
		Route:      k.Endpoints.EncryptRoute,
	}

	if input == nil {
		input = &EncryptInput{}
	}

	output = &EncryptOutput{}
	req = k.newRequest(op, input, output)

	return
}

// Decryption
const opDecrypt = "Decrypt"

// DecryptInput contains a payload to be decrypted by DuoKey.
type DecryptInput struct {
	ID        uint32            `json:"id"`
	KeyID     string            `json:"keyid"`
	VaultID   string            `json:"vaultid"`
	Algorithm string            `json:"algorithm,omitempty"`
	Context   map[string]string `json:"context,omitempty"`
	Payload   []byte            `json:"payload"`
}

// DecryptOutput contains the deserialized payload returned by the DuoKey server.
type DecryptOutput struct {
	Success bool `json:"success"`
	Result  struct {
		KeyID     string `json:"keyid"`
		Algorithm string `json:"algorithm"`
		Payload   []byte `json:"payload"`
		ID        uint32 `json:"id"`
	} `json:"result"`
	TargetURL           *string `json:"targetUrl"`
	Error               *string `json:"error"`
	UnauthorizedRequest bool    `json:"unAuthorizedRequest"`
	ABP                 bool    `json:"__abp"`
}

func validateDecryptInput(input *DecryptInput) error {
	if input.KeyID == "" {
		return fmt.Errorf("The key ID cannot be an empty string")
	}

	if input.VaultID == "" {
		return fmt.Errorf("The vault ID cannot be an empty string")
	}

	return nil
}

// Decrypt API operation for DuoKey
func (k *KMS) Decrypt(input *DecryptInput) (*DecryptOutput, error) {
	
	if err := validateDecryptInput(input); err != nil {
		return nil, err
	}

	req, out := k.decryptRequest(input)

	return out, req.Send()
}

// DecryptWithContext is the same operation as Decrypt. It is however possible
// to pass a non-nil context.
func (k *KMS) DecryptWithContext(ctx context.Context, input *DecryptInput) (*DecryptOutput, error) {

	if err := validateDecryptInput(input); err != nil {
		return nil, err
	}
	
	req, out := k.decryptRequest(input)
	req.SetContext(ctx)

	return out, req.Send()
}

func (k *KMS) decryptRequest(input *DecryptInput) (req *request.Request, output *DecryptOutput) {

	op := &request.Operation{
		Name:       opDecrypt,
		HTTPMethod: http.MethodPost,
		BaseURL:    k.Endpoints.BaseURL,
		Route:      k.Endpoints.DecryptRoute,
	}

	if input == nil {
		input = &DecryptInput{}
	}

	output = &DecryptOutput{}
	req = k.newRequest(op, input, output)

	return
}

// Helpers

func (k *KMS) newRequest(op *request.Operation, params interface{}, data interface{}) *request.Request {
	req := k.NewRequest(op, params, data)

	return req
}
