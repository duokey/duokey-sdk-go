package vault

import (
	"context"
	"net/http"

	"github.com/duokey/duokey-sdk-go/duokey/request"
)

// SealInput ...
type SealInput struct {
	// KeyID
	KeyID     string `json:"keyid"`
	Plaintext []byte `json:"plain"`
}

// SealOutput ...
type SealOutput struct {
	Ciphertext []byte `json:"cipher"`
}

// UnsealInput ...
type UnsealInput struct {
	Ciphertext []byte `json:"cipher"`
}

// UnsealOutput ...
type UnsealOutput struct {
	Plaintext []byte `json:"plain"`
}

const opSeal = "Seal"

// SealRequest ...
func (v *Vault) SealRequest(ctx context.Context, input *SealInput) (req *request.Request, output *SealOutput) {

	op := &request.Operation{
		Name:       opSeal,
		HTTPMethod: http.MethodPost,
		HTTPPath:   "/api/services/app/Keys/GetKeyId",
	}

	if input == nil {
		input = &SealInput{}
	}

	output = &SealOutput{}
	req = v.newRequest(op, input, output)

	return
}

// Seal ...
func (v *Vault) Seal(input *SealInput) (*SealOutput, error) {
	req, out := v.SealRequest(context.Background(), input)

	return out, req.Send()
}

const opUnseal = "Unseal"

// UnsealRequest ...
func (v *Vault) UnsealRequest(ctx context.Context, input *UnsealInput) (req *request.Request, output *UnsealOutput) {

	op := &request.Operation{
		Name:       opUnseal,
		HTTPMethod: http.MethodPost,
		HTTPPath:   "/",
	}

	if input == nil {
		input = &UnsealInput{}
	}

	output = &UnsealOutput{}
	req = v.newRequest(op, input, output)

	return
}

// Unseal ...
func (v *Vault) Unseal(input *UnsealInput) (*UnsealOutput, error) {
	return nil, nil
}
