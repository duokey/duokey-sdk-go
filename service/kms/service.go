package kms

import (
	"github.com/duokey/duokey-sdk-go/duokey"
	"github.com/duokey/duokey-sdk-go/duokey/client"
	"github.com/duokey/duokey-sdk-go/duokey/credentials"
)

// KMS implements the KMSAPI interface
type KMS struct {
	*client.Client
	*Endpoints
}

// Endpoints of the crypto services (all routes of the DuoKey REST API
// are customizable)
type Endpoints struct {
	BaseURL                 string `mapstructure:"base-url"`
	CreateKeyRoute          string `mapstructure:"createkey-route"`
	DeleteKeyRoute          string `mapstructure:"deletekey-route"`
	EncryptRoute            string `mapstructure:"encrypt-route"`
	DecryptRoute            string `mapstructure:"decrypt-route"`
	ImportRoute             string `mapstructure:"import-route"`
	GetKeyIdRoute           string `mapstructure:"getkeyid-route"`
	GetKeyByNameRoute       string `mapstructure:"getkeybyname-route"`
	GetAllKeysRoute         string `mapstructure:"getallkeys-route"`
	CSRImportRoute          string `mapstructure:"csrimport-route"`
	CSRStatusRoute          string `mapstructure:"csrstatus-route"`
	GetSignatureCARoute     string `mapstructure:"getsignatureca-route"`
	CreateOrEditObjectRoute string `mapstructure:"createoreditobject-route"`
	GetObjectByNameRoute    string `mapstructure:"getobjectbyname-route"`
	GetObjectByIdRoute      string `mapstructure:"getobjectbyid-route"`
}

// New checks the credentials and returns a KMS client with the default logger.
// checkTokenTimeOut: The timeout in seconds for the cockpit call to get/check the token is optional with a default value if not passed
func NewClient(credentials credentials.Config, endpoints Endpoints, checkTokenTimeOut ...int) (*KMS, error) {
	checkTokenTimeOutSeconds := 10

	if len(checkTokenTimeOut) > 0 {
		checkTokenTimeOutSeconds = checkTokenTimeOut[0]
	}
	return NewClientWithLogger(credentials, endpoints, nil, checkTokenTimeOutSeconds)
}

// New checks the credentials and returns a KMS client with a custom logger.
// checkTokenTimeOut: The timeout in seconds for the cockpit call to get/check the token is optional with a default value if not passed
func NewClientWithLogger(credentials credentials.Config, endpoints Endpoints, logger duokey.Logger, checkTokenTimeOut ...int) (*KMS, error) {
	checkTokenTimeOutSeconds := 10

	if len(checkTokenTimeOut) > 0 {
		checkTokenTimeOutSeconds = checkTokenTimeOut[0]
	}

	client, err := client.New(credentials, logger, checkTokenTimeOutSeconds)
	if err != nil {
		return nil, err
	}

	// Set default routes values if no specific value was set
	if endpoints.CreateKeyRoute == "" {
		endpoints.CreateKeyRoute = "/api/services/app/Keys/CreateOrEdit"
	}
	if endpoints.DeleteKeyRoute == "" {
		endpoints.DeleteKeyRoute = "/api/services/app/Keys/Delete"
	}
	if endpoints.EncryptRoute == "" {
		endpoints.EncryptRoute = "/api/services/app/Keys/CreateEncryptRequest"
	}
	if endpoints.DecryptRoute == "" {
		endpoints.DecryptRoute = "/api/services/app/Keys/CreateDecryptRequest"
	}
	if endpoints.ImportRoute == "" {
		endpoints.ImportRoute = "/api/services/app/Keys/Import"
	}
	if endpoints.GetKeyIdRoute == "" {
		endpoints.GetKeyIdRoute = "/api/services/app/Keys/GetKeyId"
	}
	if endpoints.GetKeyByNameRoute == "" {
		endpoints.GetKeyByNameRoute = "/api/services/app/Keys/GetKeyByName"
	}
	if endpoints.GetAllKeysRoute == "" {
		endpoints.GetAllKeysRoute = "/api/services/app/Keys/GetAll"
	}
	if endpoints.CSRImportRoute == "" {
		endpoints.CSRImportRoute = "/api/services/app/CertificateRequests/ImportCertificateCSR"
	}
	if endpoints.CSRStatusRoute == "" {
		endpoints.CSRStatusRoute = "/api/services/app/CertificateRequests/CertificateRequestStatus"
	}
	if endpoints.GetSignatureCARoute == "" {
		endpoints.GetSignatureCARoute = "/api/services/app/SCEP/GetSignatureCAForScepServer"
	}
	if endpoints.CreateOrEditObjectRoute == "" {
		endpoints.CreateOrEditObjectRoute = "/api/services/app/pkcs11/CreateOrEditObject"
	}
	if endpoints.GetObjectByNameRoute == "" {
		endpoints.GetObjectByNameRoute = "/api/services/app/pkcs11/GetObjectByName"
	}
	if endpoints.GetObjectByIdRoute == "" {
		endpoints.GetObjectByIdRoute = "/api/services/app/pkcs11/GetObjectById"
	}
	return &KMS{Client: client, Endpoints: &endpoints}, nil
}
