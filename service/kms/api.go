package kms

import (
	"context"
	"net/http"

	"github.com/duokey/duokey-sdk-go/duokey/request"
)

// EncryptInput contains a plaintext to be encrypted by DuoKey. DuoKey determines the encryption 
// algorithm from the VaultID and KeyId. The optional field Algorithm allows you to specify a 
// chaining mode or a padding scheme. An initial vector or a tag can be supplied using the 
// Context field.
type EncryptInput struct {
	KeyID     string             `json:"keyid"`
	VaultID   string             `json:"vaultid"`
	Algorithm string             `json:"algorithm,omitempty"`
	Context   map[string]*string `json:"context,omitempty"`
	Plaintext []byte             `json:"plain"`
}

// EncryptOutput contains the deserialized payload returned by the DuoKey server.
type EncryptOutput struct {
	KeyID      string `json:"keyid"`
	Algorithm  string `json:"algorithm,omitempty"`
	Ciphertext []byte `json:"cipher"`
}

// DecryptInput contains a ciphertext to be decrypted by DuoKey.
type DecryptInput struct {
	KeyID      string             `json:"keyid"`
	VaultID    string             `json:"vaultid"`
	Algorithm  string             `json:"algorithm,omitempty"`
	Context    map[string]*string `json:"context,omitempty"`
	Ciphertext []byte             `json:"cipher"`
}

// DecryptOutput contains the deserialized payload returned by the DuoKey server.
type DecryptOutput struct {
	KeyID     string `json:"keyid"`
	Algorithm string `json:"algorithm,omitempty"`
	Plaintext []byte `json:"plain"`
}

const opEncrypt = "Encrypt"

func (k *KMS) encryptRequest(ctx context.Context, input *EncryptInput) (req *request.Request, output *EncryptOutput) {

	op := &request.Operation{
		Name:       opEncrypt,
		HTTPMethod: http.MethodPost,
		HTTPPath:   k.Config.Routes.KMSEncrypt,
	}

	if input == nil {
		input = &EncryptInput{}
	}

	output = &EncryptOutput{}
	req = k.newRequest(op, input, output)

	return
}

// Encrypt API operation for DuoKey
func (k *KMS) Encrypt(input *EncryptInput) (*EncryptOutput, error) {
	req, out := k.encryptRequest(context.Background(), input)

	return out, req.Send()
}

const opDecrypt = "Decrypt"

func (k *KMS) decryptRequest(ctx context.Context, input *DecryptInput) (req *request.Request, output *DecryptOutput) {

	op := &request.Operation{
		Name:       opDecrypt,
		HTTPMethod: http.MethodPost,
		HTTPPath:   k.Config.Routes.KMSDecrypt,
	}

	if input == nil {
		input = &DecryptInput{}
	}

	output = &DecryptOutput{}
	req = k.newRequest(op, input, output)

	return
}

// Decrypt API operation for DuoKey
func (k *KMS) Decrypt(input *DecryptInput) (*DecryptOutput, error) {
	req, out := k.decryptRequest(context.Background(), input)

	return out, req.Send()
}
