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
	BaseURL             string `mapstructure:"base-url"`
	CreateKeyRoute      string `mapstructure:"createkey-route"`
	DeleteKeyRoute      string `mapstructure:"deletekey-route"`
	EncryptRoute        string `mapstructure:"encrypt-route"`
	DecryptRoute        string `mapstructure:"decrypt-route"`
	ImportRoute         string `mapstructure:"import-route"`
	GetKeyIdRoute       string `mapstructure:"getkeyid-route"`
	CSRImportRoute      string `mapstructure:"csrimport-route"`
	CSRStatusRoute      string `mapstructure:"csrstatus-route"`
	GetSignatureCARoute string `mapstructure:"getsignatureca-route"`
}

// New checks the credentials and returns a KMS client with the default logger.
func NewClient(credentials credentials.Config, endpoints Endpoints) (*KMS, error) {
	return NewClientWithLogger(credentials, endpoints, nil)
}

// New checks the credentials and returns a KMS client with a custom logger.
func NewClientWithLogger(credentials credentials.Config, endpoints Endpoints, logger duokey.Logger) (*KMS, error) {
	client, err := client.New(credentials, logger)
	if err != nil {
		return nil, err
	}

	// Set default routes values if no specific value was set
	if endpoints.CreateKeyRoute == "" {
		endpoints.CreateKeyRoute = "api/services/app/Keys/CreateOrEdit"
	}
	if endpoints.DeleteKeyRoute == "" {
		endpoints.DeleteKeyRoute = "api/services/app/Keys/Delete"
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
	if endpoints.CSRImportRoute == "" {
		endpoints.CSRImportRoute = "/api/services/app/CertificateRequests/ImportCertificateCSR"
	}
	if endpoints.CSRStatusRoute == "" {
		endpoints.CSRStatusRoute = "/api/services/app/CertificateRequests/CertificateRequestStatus"
	}
	if endpoints.GetSignatureCARoute == "" {
		endpoints.GetSignatureCARoute = "/api/services/app/SCEP/GetSignatureCAForScepServer"
	}

	return &KMS{Client: client, Endpoints: &endpoints}, nil
}
