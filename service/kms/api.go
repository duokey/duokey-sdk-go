package kms

import (
	"context"
	"net/http"

	"github.com/duokey/duokey-sdk-go/duokey/request"
	"github.com/google/go-querystring/query"
)

// Import
const opImport = "Import"

type ImportInput struct {
	ID      uint32            `json:"id"`
	VaultID string            `json:"vaultid" validate:"nonzero"`
	Context map[string]string `json:"context,omitempty"`
	Payload []byte            `json:"payload"`
}

type ImportOutput struct {
	Success bool `json:"success"`
	Result  struct {
		KeyID string `json:"keyid" validate:"nonzero"`
		KCV   string `json:"kcv"`
		ID    uint32 `json:"id"`
	} `json:"result" validate:"nonzero"`
	TargetURL           *string `json:"targetUrl"`
	Error               *string `json:"error"`
	UnauthorizedRequest bool    `json:"unAuthorizedRequest"`
	ABP                 bool    `json:"__abp"`
}

func (k *KMS) Import(input *ImportInput) (*ImportOutput, error) {
	req, out := k.importRequest(input)

	return out, req.Send()
}

func (k *KMS) ImportWithContext(ctx context.Context, input *ImportInput) (*ImportOutput, error) {
	req, out := k.importRequest(input)
	req.SetContext(ctx)

	return out, req.Send()
}

func (k *KMS) importRequest(input *ImportInput) (req *request.Request, output *ImportOutput) {

	op := &request.Operation{
		Name:       opImport,
		HTTPMethod: http.MethodPost,
		BaseURL:    k.Endpoints.BaseURL,
		Route:      k.Endpoints.ImportRoute,
	}

	if input == nil {
		input = &ImportInput{}
	}

	// Create an empty context if needed
	if input.Context == nil {
		input.Context = make(map[string]string)
	}

	// Merge the input context and the mandatory context
	for key, value := range k.Client.GetMandatoryContext() {
		input.Context[key] = value
	}

	output = &ImportOutput{}
	req = k.NewRequest(op, input, output)

	return
}

// Encryption
const opEncrypt = "Encrypt"

// EncryptInput contains a payload to be encrypted by DuoKey. DuoKey determines the encryption
// algorithm from the VaultID and KeyId. The optional field Algorithm allows you to specify a
// chaining mode or a padding scheme. An initial vector or a tag can be supplied using the
// Context field.
// Validation is done by calling request.New.
type EncryptInput struct {
	ID        uint32            `json:"id"`
	KeyID     string            `json:"keyid" validate:"nonzero"`
	VaultID   string            `json:"vaultid" validate:"nonzero"`
	Algorithm string            `json:"algorithm,omitempty"`
	Context   map[string]string `json:"context,omitempty"`
	Payload   []byte            `json:"payload"`
}

// EncryptOutput contains the deserialized payload returned by the DuoKey server.
// Validation is done by calling request.Send.
// For AES-GCM operation, the Iv is also found in the payload and needed for the decrypt operation
type EncryptOutput struct {
	Success bool `json:"success"`
	Result  struct {
		KeyID            string `json:"keyid" validate:"nonzero"`
		Algorithm        string `json:"algorithm"`
		EncryptedPayload string `json:"encryptedPayload" validate:"nonzero"`
		ID               uint32 `json:"id"`
		Iv               string `json:"initializationVector"`
	} `json:"result" validate:"nonzero"`
	TargetURL           *string `json:"targetUrl"`
	Error               *string `json:"error"`
	UnauthorizedRequest bool    `json:"unAuthorizedRequest"`
	ABP                 bool    `json:"__abp"`
}

// Encrypt API operation for DuoKey
func (k *KMS) Encrypt(input *EncryptInput) (*EncryptOutput, error) {

	req, out := k.encryptRequest(input)

	return out, req.Send()
}

// EncryptWithContext is the same operation as Encrypt. It is however possible
// to pass a non-nil context.
func (k *KMS) EncryptWithContext(ctx context.Context, input *EncryptInput) (*EncryptOutput, error) {

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

	// Create an empty context if needed
	if input.Context == nil {
		input.Context = make(map[string]string)
	}

	// Merge the input context and the mandatory context
	for key, value := range k.Client.GetMandatoryContext() {
		input.Context[key] = value
	}

	output = &EncryptOutput{}
	req = k.NewRequest(op, input, output)

	return
}

// Decryption
const opDecrypt = "Decrypt"

// DecryptInput contains a payload to be decrypted by DuoKey.
// An Iv can be passed if needed
// Validation is done by calling request.New.
type DecryptInput struct {
	ID        uint32            `json:"id"`
	KeyID     string            `json:"keyid" validate:"nonzero"`
	VaultID   string            `json:"vaultid" validate:"nonzero"`
	Algorithm string            `json:"algorithm,omitempty"`
	Context   map[string]string `json:"context,omitempty"`
	Payload   string            `json:"payload"`
	Iv        string            `json:"iv"`
}

// DecryptOutput contains the deserialized payload returned by the DuoKey server.
// Validation is done by calling request.Send.
type DecryptOutput struct {
	Success bool `json:"success"`
	Result  struct {
		KeyID     string `json:"keyid" validate:"nonzero"`
		Algorithm string `json:"algorithm"`
		Payload   []byte `json:"payload" validate:"nonzero"`
		ID        uint32 `json:"id"`
	} `json:"result" validate:"nonzero"`
	TargetURL           *string `json:"targetUrl"`
	Error               *string `json:"error"`
	UnauthorizedRequest bool    `json:"unAuthorizedRequest"`
	ABP                 bool    `json:"__abp"`
}

// Decrypt API operation for DuoKey
func (k *KMS) Decrypt(input *DecryptInput) (*DecryptOutput, error) {

	req, out := k.decryptRequest(input)

	return out, req.Send()
}

// DecryptWithContext is the same operation as Decrypt. It is however possible
// to pass a non-nil context.
func (k *KMS) DecryptWithContext(ctx context.Context, input *DecryptInput) (*DecryptOutput, error) {

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

	// Create an empty context if needed
	if input.Context == nil {
		input.Context = make(map[string]string)
	}

	// Merge the input context and the mandatory context
	for key, value := range k.Client.GetMandatoryContext() {
		input.Context[key] = value
	}

	output = &DecryptOutput{}
	req = k.NewRequest(op, input, output)

	return
}

// GetKeyId
const opGetKeyId = "GetKeyId"

// GetKeyIdInput retrives key information.
type GetKeyIdInput struct {
	ExternalID string `schema:"externalId" url:"externalId"`
}

type KeyData struct {
	Name             string `json:"name"`
	Size             int    `json:"size"`
	PublicKey        string `json:"publicKey"`
	IsEnabled        bool   `json:"isEnabled"`
	State            int    `json:"state"`
	ExternalId       string `json:"externalId"`
	ActivationTime   string `json:"activationTime"`
	IsDecrypt        bool   `json:"isDecrypt"`
	IsEncrypt        bool   `json:"isEncrypt"`
	IsWrap           bool   `json:"isWrap"`
	IsUnwrap         bool   `json:"isUnwrap"`
	IsDeriveKey      bool   `json:"isDeriveKey"`
	IsMacGenerate    bool   `json:"isMacGenerate"`
	IsMacVerify      bool   `json:"isMacVerify"`
	IsAppManageable  bool   `json:"isAppManageable"`
	IsSign           bool   `json:"isSign"`
	IsVerify         bool   `json:"isVerify"`
	IsAgreeKey       bool   `json:"isAgreeKey"`
	IsExport         bool   `json:"isExport"`
	IsAuditLogEnable bool   `json:"isAuditLogEnable"`
	Type             string `json:"type"`
	DeactivationTime string `json:"deactivationTime"`
	Reason           int    `json:"reason"`
	CompromiseTime   string `json:"compromiseTime"`
	Comment          string `json:"comment"`
	PublishPublicKey bool   `json:"publishPublicKey"`
	VaultId          string `json:"vaultId"`
	Id               string `json:"id"`
}

// GetKeyIdOutput contains key information.
// Validation is done by calling request.Send.
type GetKeyIdOutput struct {
	Success bool `json:"success"`
	Result  struct {
		Key       KeyData `json:"key" validate:"nonzero"`
		VaultName string  `json:"vaultName"`
		VaultType uint32  `json:"vaultType"`
	} `json:"result" validate:"nonzero"`
	TargetURL           *string `json:"targetUrl"`
	Error               *string `json:"error"`
	UnauthorizedRequest bool    `json:"unAuthorizedRequest"`
	ABP                 bool    `json:"__abp"`
}

// Get Key By Id
func (k *KMS) GetKeyId(input *GetKeyIdInput) (*GetKeyIdOutput, error) {

	req, out := k.getKeyIdRequest(input)

	return out, req.Send()
}

// GetKeyIdWithContext is the same operation as GetKeyId. It is however possible
// to pass a non-nil context.
func (k *KMS) GetKeyIdWithContext(ctx context.Context, input *GetKeyIdInput) (*GetKeyIdOutput, error) {

	req, out := k.getKeyIdRequest(input)
	req.SetContext(ctx)

	return out, req.Send()
}

func (k *KMS) getKeyIdRequest(input *GetKeyIdInput) (req *request.Request, output *GetKeyIdOutput) {

	// This is used to get query parameter format from struct =>  queryParams ::  map[externalId:[2e974659-64e8-4e8a-b702-c5133620bd0f]]
	// queryParams.Encode() will convert it into string query parameter => externalId=2e974659-64e8-4e8a-b702-c5133620bd0f
	queryParams, _ := query.Values(input)

	op := &request.Operation{
		Name:        opGetKeyId,
		HTTPMethod:  http.MethodGet,
		BaseURL:     k.Endpoints.BaseURL,
		Route:       k.Endpoints.GetKeyIdRoute,
		QueryParams: queryParams.Encode(),
	}

	if input == nil {
		input = &GetKeyIdInput{}
	}

	output = &GetKeyIdOutput{}
	req = k.NewRequest(op, input, output)

	return
}

// CSR Import
const opCSRImport = "CSRImport"

type CSRImportInput struct {
	CSR string `schema:"csr" url:"csr"`
}

type CSRImportOutput struct {
	Success             bool    `json:"success"`
	Error               *string `json:"error"`
	UnauthorizedRequest bool    `json:"unAuthorizedRequest"`
}

func (k *KMS) CSRImport(input *CSRImportInput) (*CSRImportOutput, error) {
	req, out := k.csrImportRequest(input)

	return out, req.Send()
}

func (k *KMS) CSRImportWithContext(ctx context.Context, input *CSRImportInput) (*CSRImportOutput, error) {

	req, out := k.csrImportRequest(input)
	req.SetContext(ctx)

	return out, req.Send()
}

func (k *KMS) csrImportRequest(input *CSRImportInput) (req *request.Request, output *CSRImportOutput) {
	op := &request.Operation{
		Name:       opCSRImport,
		HTTPMethod: http.MethodPost,
		BaseURL:    k.Endpoints.BaseURL,
		Route:      k.Endpoints.CSRImportRoute,
	}

	if input == nil {
		input = &CSRImportInput{}
	}

	output = &CSRImportOutput{}
	req = k.NewRequest(op, input.CSR, output)

	return
}

// CSR Status
const opCSRStatus = "CSRStatus"

type CSRStatusInput struct {
	CommonName string `schema:"commonName" url:"commonName"`
}

type CSRStatusOutput struct {
	Success bool `json:"success"`
	Result  struct {
		Status      string `json:"status"`
		Certificate string `json:"certificate"`
	} `json:"result" validate:"nonzero"`
}

func (k *KMS) CSRStatus(input *CSRStatusInput) (*CSRStatusOutput, error) {
	req, out := k.csrStatusRequest(input)

	return out, req.Send()
}

func (k *KMS) CSRStatusWithContext(ctx context.Context, input *CSRStatusInput) (*CSRStatusOutput, error) {

	req, out := k.csrStatusRequest(input)
	req.SetContext(ctx)

	return out, req.Send()
}

func (k *KMS) csrStatusRequest(input *CSRStatusInput) (req *request.Request, output *CSRStatusOutput) {
	// commonName is passed as query parameter
	queryParams, _ := query.Values(input)

	op := &request.Operation{
		Name:        opCSRStatus,
		HTTPMethod:  http.MethodPost,
		BaseURL:     k.Endpoints.BaseURL,
		Route:       k.Endpoints.CSRStatusRoute,
		QueryParams: queryParams.Encode(),
	}

	if input == nil {
		input = &CSRStatusInput{}
	}

	output = &CSRStatusOutput{}
	req = k.NewRequest(op, input, output)

	return
}
