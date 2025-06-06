package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"

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

// Create Key
const opCreateKey = "CreateKey"

type CreateKeyInput struct {
	VaultID          string            `json:"vaultid" validate:"nonzero"`
	Context          map[string]string `json:"context,omitempty"`
	KeyName          string            `json:"name,omitempty"`
	KeyType          string            `json:"type,omitempty"`
	KeySize          int               `json:"size,omitempty"`
	Description      string            `json:"description,omitempty"`
	Comment          string            `json:"comment,omitempty"`
	IsDecrypt        bool              `json:"isDecrypt,omitempty"`
	IsEncrypt        bool              `json:"isEncrypt,omitempty"`
	IsSign           bool              `json:"isSign,omitempty"`
	IsVerify         bool              `json:"isVerify,omitempty"`
	Id               string            `json:"id,omitempty"`
	IsEnabled        bool              `json:"isEnabled,omitempty"`
	State            int               `json:"state,omitempty"` // 0 = preActive, 1=active
	IsWrap           bool              `json:"isWrap,omitempty"`
	IsUnwrap         bool              `json:"isUnwrap,omitempty"`
	IsDeriveKey      bool              `json:"isDeriveKey,omitempty"`
	IsMacGenerate    bool              `json:"isMacGenerate,omitempty"`
	IsMacVerify      bool              `json:"isMacVerify,omitempty"`
	IsAppManageable  bool              `json:"isAppManageable,omitempty"`
	IsAgreeKey       bool              `json:"isAgreeKey,omitempty"`
	IsExport         bool              `json:"isExport,omitempty"`
	IsAuditLogEnable bool              `json:"isAuditLogEnable,omitempty"`
	PublishPublicKey bool              `json:"publishPublicKey,omitempty"`
	Reason           int               `json:"reason,omitempty"`
}

type CreateKeyOutput struct {
	Success    bool   `json:"success,omitempty"`
	ExternalId string `json:"result"`
}

// SuccessOutput can be used as the output of different routes that return a Success boolean
type SuccessOutput struct {
	Success bool `json:"success,omitempty"`
}

// CreateKey API operation for DuoKey
func (k *KMS) CreateKey(input *CreateKeyInput) (*CreateKeyOutput, error) {

	req, out := k.createKeyRequest(input)

	return out, req.Send()
}

// CreateKeyWithContext is the same operation as CreateKey. It is however possible
// to pass a non-nil context.
func (k *KMS) CreateKeyWithContext(ctx context.Context, input *CreateKeyInput) (*CreateKeyOutput, error) {

	req, out := k.createKeyRequest(input)
	req.SetContext(ctx)

	return out, req.Send()
}

func (k *KMS) createKeyRequest(input *CreateKeyInput) (req *request.Request, output *CreateKeyOutput) {

	op := &request.Operation{
		Name:       opCreateKey,
		HTTPMethod: http.MethodPost,
		BaseURL:    k.Endpoints.BaseURL,
		Route:      k.Endpoints.CreateKeyRoute,
	}

	if input == nil {
		input = &CreateKeyInput{}
	}

	// Create an empty context if needed
	if input.Context == nil {
		input.Context = make(map[string]string)
	}

	// Merge the input context and the mandatory context
	for key, value := range k.Client.GetMandatoryContext() {
		input.Context[key] = value
	}

	output = &CreateKeyOutput{}
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
	Iv        []byte            `json:"iv"`
	Aad       []byte            `json:"aad"`
}

// EncryptOutput contains the deserialized payload returned by the DuoKey server.
// Validation is done by calling request.Send.
type EncryptOutput struct {
	Success bool `json:"success"`
	Result  struct {
		KeyID            string `json:"keyid" validate:"nonzero"`
		Algorithm        string `json:"algorithm"`
		EncryptedPayload string `json:"encryptedPayload" validate:"nonzero"`
		ID               uint32 `json:"id"`
		Iv               string `json:"initializationVector"`
		Tag              string `json:"messageAuthenticationCode"`
	} `json:"result" validate:"nonzero"`
	TargetURL           *string `json:"targetUrl"`
	Error               *string `json:"error"`
	UnauthorizedRequest bool    `json:"unAuthorizedRequest"`
	ABP                 bool    `json:"__abp"`
}

// Encrypt API operation for DuoKey
func (k *KMS) Encrypt(input *EncryptInput) (*EncryptOutput, error) {

	return k.encryptRequest(input, nil)
}

// EncryptWithContext is the same operation as Encrypt. It is however possible
// to pass a non-nil context.
func (k *KMS) EncryptWithContext(ctx context.Context, input *EncryptInput) (*EncryptOutput, error) {

	return k.encryptRequest(input, ctx)
}

// Since 2024 the cockpit no more handles RSA Encryption
//
//	RSA encryption must be performed by the client
func (k *KMS) encryptRequest(input *EncryptInput, ctx context.Context) (*EncryptOutput, error) {
	if strings.HasPrefix(input.Algorithm, "RSA") {
		return k.encryptRequestRSAByClient(input, ctx)
	} else {
		req, out := k.encryptRequestByCockpit(input)
		if ctx != nil {
			req.SetContext(ctx)
		}

		return out, req.Send()
	}
}

// RSA Encryption is performed by the client
//
//	The RSA key data is queried from the Cockpit witha getKeyById
func (k *KMS) encryptRequestRSAByClient(input *EncryptInput, ctx context.Context) (*EncryptOutput, error) {
	// Request the RSA key information
	getKeyIdInput := GetKeyIdInput{
		ExternalID: input.KeyID,
	}

	var getKeyIdOutput *GetKeyOutput
	var err error

	if ctx != nil {
		getKeyIdOutput, err = k.GetKeyIdWithContext(ctx, &getKeyIdInput)
	} else {
		getKeyIdOutput, err = k.GetKeyId(&getKeyIdInput)
	}

	if err != nil {
		return nil, err
	}

	// Create a rsa Public Key object from the string returned by the cockpit (that does not contain header/footer)
	pubKeyPEM := "-----BEGIN PUBLIC KEY-----\n" + getKeyIdOutput.Result.Key.PublicKey + "\n-----END PUBLIC KEY-----"

	// Decode the PEM string to get the public key
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("Failed to decode PEM block containing the public key")
	}

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("Failed to parse public key:" + err.Error())
	}

	// Type assert the public key to rsa.PublicKey type
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Not an RSA public key")
	}

	label := []byte("") // Optional, used for OAEP encryption, can be left empty

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, input.Payload, label)
	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertext)

	// Prepare the result
	output := &EncryptOutput{}
	output.Success = true
	output.Result.KeyID = input.KeyID
	output.Result.Algorithm = input.Algorithm
	output.Result.EncryptedPayload = ciphertextB64
	output.Result.ID = input.ID

	return output, nil

}

func (k *KMS) encryptRequestByCockpit(input *EncryptInput) (req *request.Request, output *EncryptOutput) {
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
// Iv/Aad/Tag can be passed if needed depending on the algorithm
// Validation is done by calling request.New.
type DecryptInput struct {
	ID        uint32            `json:"id"`
	KeyID     string            `json:"keyid" validate:"nonzero"`
	VaultID   string            `json:"vaultid" validate:"nonzero"`
	Algorithm string            `json:"algorithm,omitempty"`
	Context   map[string]string `json:"context,omitempty"`
	Payload   string            `json:"payload"`
	Iv        []byte            `json:"iv"`
	Aad       []byte            `json:"aad"`
	Tag       string            `json:"tag"`
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

// GetKeyOutput contains key information, from getKeyID or getKeyByName requests
// Validation is done by calling request.Send.
type GetKeyOutput struct {
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
func (k *KMS) GetKeyId(input *GetKeyIdInput) (*GetKeyOutput, error) {

	req, out := k.getKeyIdRequest(input)

	return out, req.Send()
}

// GetKeyIdWithContext is the same operation as GetKeyId. It is however possible
// to pass a non-nil context.
func (k *KMS) GetKeyIdWithContext(ctx context.Context, input *GetKeyIdInput) (*GetKeyOutput, error) {

	req, out := k.getKeyIdRequest(input)
	req.SetContext(ctx)

	return out, req.Send()
}

func (k *KMS) getKeyIdRequest(input *GetKeyIdInput) (req *request.Request, output *GetKeyOutput) {

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

	output = &GetKeyOutput{}
	req = k.NewRequest(op, input, output)

	return
}

// GetKeyByName
const opGetKeyByName = "GetKeyByName"

// GetKeyIdInput retrives key information.
type GetKeyByNameInput struct {
	Name string `schema:"name" url:"name"`
}

// Get Key by Name
func (k *KMS) GetKeyByName(input *GetKeyByNameInput) (*GetKeyOutput, error) {

	req, out := k.getKeyByNameRequest(input)

	return out, req.Send()
}

// GetKeyByNameWithContext is the same operation as GetKeyByName. It is however possible
// to pass a non-nil context.
func (k *KMS) GetKeyByNameWithContext(ctx context.Context, input *GetKeyByNameInput) (*GetKeyOutput, error) {

	req, out := k.getKeyByNameRequest(input)
	req.SetContext(ctx)

	return out, req.Send()
}

func (k *KMS) getKeyByNameRequest(input *GetKeyByNameInput) (req *request.Request, output *GetKeyOutput) {

	// This is used to get query parameter format from struct
	// queryParams.Encode() will convert it into string
	queryParams, _ := query.Values(input)

	op := &request.Operation{
		Name:        opGetKeyByName,
		HTTPMethod:  http.MethodGet,
		BaseURL:     k.Endpoints.BaseURL,
		Route:       k.Endpoints.GetKeyByNameRoute,
		QueryParams: queryParams.Encode(),
	}

	if input == nil {
		input = &GetKeyByNameInput{}
	}

	output = &GetKeyOutput{}
	req = k.NewRequest(op, input, output)

	return
}

// DeleteKey
const opDeleteKey = "DeleteKey"

// DeletekeyKeyInput retrives key information.
// Id: the internal Id of the key (and not the ExternalID)
// Id can be retrieved by calling GetKeyByName, and then found in Result.Key.Id
type DeletekeyKeyInput struct {
	Id string `schema:"id" url:"id"`
}

// Delete key
func (k *KMS) DeleteKey(input *DeletekeyKeyInput) (*SuccessOutput, error) {

	req, out := k.deleteKeyRequest(input)

	return out, req.Send()
}

// DeleteKeyWithContext is the same operation as DeleteKey. It is however possible
// to pass a non-nil context.
func (k *KMS) DeleteKeyWithContext(ctx context.Context, input *DeletekeyKeyInput) (*SuccessOutput, error) {

	req, out := k.deleteKeyRequest(input)
	req.SetContext(ctx)

	return out, req.Send()
}

func (k *KMS) deleteKeyRequest(input *DeletekeyKeyInput) (req *request.Request, output *SuccessOutput) {

	// This is used to get query parameter format from struct
	// queryParams.Encode() will convert it into string
	queryParams, _ := query.Values(input)

	op := &request.Operation{
		Name:        opDeleteKey,
		HTTPMethod:  http.MethodDelete,
		BaseURL:     k.Endpoints.BaseURL,
		Route:       k.Endpoints.DeleteKeyRoute,
		QueryParams: queryParams.Encode(),
	}

	if input == nil {
		input = &DeletekeyKeyInput{}
	}

	output = &SuccessOutput{}
	req = k.NewRequest(op, input, output)

	return
}

// CSR Import
const opCSRImport = "CSRImport"

// AppID is the standard parameter for the sdk
//		It is the Cockpit's App which is, in that case, a SCEP app
//		it is used by the cockpit to know which CA issuer to use to sign the CSR
//
// RequestId is a transactionID received from a SCEP client for instance
// 		and that should be identical for the CSR upload + the CSR status operation

type Context struct {
	TransactionID string `json:"transactionid"`
	AppID         string `json:"appid"`
}

type CSRImportInput struct {
	CSR     string  `json:"csr"`
	Context Context `json:"context"`
}

type CSRImportOutput struct {
	Success bool `json:"success"`
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
	req = k.NewRequest(op, input, output)

	return
}

// CSR Status
const opCSRStatus = "CSRStatus"

// See CSRImportInput struct for some details
// Those values are not passed as json, but as query params
type CSRStatusInput struct {
	CommonName    string `schema:"commonName" url:"commonName"`
	TransactionID string `schema:"transactionId" url:"transactionId"` // `schema:"requestId" url:"requestId"`
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

// Scep Get Signature CA
const opGetSignatureCA = "GetSignatureCA"

type GetSignatureCAInput struct {
	ScepExternalId string `schema:"scepExternalId" url:"scepExternalId"`
}

type GetSignatureCAOutput struct {
	Success bool   `json:"success"`
	Result  string `json:"result" validate:"nonzero"`
}

func (k *KMS) GetSignatureCA(input *GetSignatureCAInput) (*GetSignatureCAOutput, error) {
	req, out := k.getSignatureCARequest(input)

	return out, req.Send()
}

func (k *KMS) GetSignatureCAWithContext(ctx context.Context, input *GetSignatureCAInput) (*GetSignatureCAOutput, error) {

	req, out := k.getSignatureCARequest(input)
	req.SetContext(ctx)

	return out, req.Send()
}

func (k *KMS) getSignatureCARequest(input *GetSignatureCAInput) (req *request.Request, output *GetSignatureCAOutput) {
	queryParams, _ := query.Values(input)

	op := &request.Operation{
		Name:        opGetSignatureCA,
		HTTPMethod:  http.MethodGet,
		BaseURL:     k.Endpoints.BaseURL,
		Route:       k.Endpoints.GetSignatureCARoute,
		QueryParams: queryParams.Encode(),
	}

	if input == nil {
		input = &GetSignatureCAInput{}
	}

	output = &GetSignatureCAOutput{}
	req = k.NewRequest(op, input, output)

	return
}

// Create Key
const opCreateOrEditObject = "CreateOrEditObject"

// TODO add Id or ExernalId for edition
// Description: currently hard-coded by the cockpit
type CreateOrEditObjectInput struct {
	VaultID    string            `json:"vaultid" validate:"nonzero"`
	Context    map[string]string `json:"context,omitempty"`
	ObjectName string            `json:"name,omitempty"`
	ObjectData string            `json:"objectData,omitempty"`
}

type CreateObjectOutput struct {
	Success    bool   `json:"success,omitempty"`
	ExternalId string `json:"result"`
}

// CreateKey API operation for DuoKey
func (k *KMS) CreateOrEditObject(input *CreateOrEditObjectInput) (*CreateObjectOutput, error) {

	req, out := k.createOrEditObjectRequest(input)

	return out, req.Send()
}

// CreateKeyWithContext is the same operation as CreateKey. It is however possible
// to pass a non-nil context.
func (k *KMS) CreateOrEditObjectWithContext(ctx context.Context, input *CreateOrEditObjectInput) (*CreateObjectOutput, error) {

	req, out := k.createOrEditObjectRequest(input)
	req.SetContext(ctx)

	return out, req.Send()
}

func (k *KMS) createOrEditObjectRequest(input *CreateOrEditObjectInput) (req *request.Request, output *CreateObjectOutput) {

	op := &request.Operation{
		Name:       opCreateOrEditObject,
		HTTPMethod: http.MethodPost,
		BaseURL:    k.Endpoints.BaseURL,
		Route:      k.Endpoints.CreateOrEditObjectRoute,
	}

	if input == nil {
		input = &CreateOrEditObjectInput{}
	}

	// Create an empty context if needed
	if input.Context == nil {
		input.Context = make(map[string]string)
	}

	// Merge the input context and the mandatory context
	for key, value := range k.Client.GetMandatoryContext() {
		input.Context[key] = value
	}

	output = &CreateObjectOutput{}
	req = k.NewRequest(op, input, output)

	return
}

const opGetObjectByName = "opGetObjectByName"

// GetKeyIdInput retrives key information.
type GetObjectByNameInput struct {
	Name string `schema:"name" url:"name"`
}

type ObjectData struct {
	Name       string `json:"name,omitempty"`
	VaultID    string `json:"vaultid" validate:"nonzero"`
	ObjectData string `json:"objectData,omitempty"`
	ExternalId string `json:"externalId"`
	Id         string `json:"id"`
}

type GetObjectOutput struct {
	Success bool `json:"success"`
	Result  struct {
		Object    ObjectData `json:"object" validate:"nonzero"`
		VaultName string     `json:"vaultName"`
		VaultType uint32     `json:"vaultType"`
	} `json:"result" validate:"nonzero"`
	TargetURL           *string `json:"targetUrl"`
	Error               *string `json:"error"`
	UnauthorizedRequest bool    `json:"unAuthorizedRequest"`
	ABP                 bool    `json:"__abp"`
}

// Get Key by Name
func (k *KMS) GetObjecByName(input *GetObjectByNameInput) (*GetObjectOutput, error) {

	req, out := k.getObjectByNameRequest(input)

	return out, req.Send()
}

// GetKeyByNameWithContext is the same operation as GetKeyByName. It is however possible
// to pass a non-nil context.
func (k *KMS) GetObjecByNameWithContext(ctx context.Context, input *GetObjectByNameInput) (*GetObjectOutput, error) {

	req, out := k.getObjectByNameRequest(input)
	req.SetContext(ctx)

	return out, req.Send()
}

func (k *KMS) getObjectByNameRequest(input *GetObjectByNameInput) (req *request.Request, output *GetObjectOutput) {

	// This is used to get query parameter format from struct
	// queryParams.Encode() will convert it into string
	queryParams, _ := query.Values(input)

	op := &request.Operation{
		Name:        opGetObjectByName,
		HTTPMethod:  http.MethodGet,
		BaseURL:     k.Endpoints.BaseURL,
		Route:       k.Endpoints.GetObjectByNameRoute,
		QueryParams: queryParams.Encode(),
	}

	if input == nil {
		input = &GetObjectByNameInput{}
	}

	output = &GetObjectOutput{}
	req = k.NewRequest(op, input, output)

	return
}
