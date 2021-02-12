package duokey

import (
	"net/http"

	"github.com/duokey/duokey-sdk-go/duokey/credentials"
)

// Config ...
type Config struct {
	Credentials credentials.Config
	// Issuer string
	// ClientID string
	// ClientSecret string
	// UserName string
	// Password string
	// Scope string
	// // TenantID must be copied into the header of each request
	// TenantID uint32
	// Endpoint string
		
	// The HTTP client to use when sending requests. Defaults to
	// `http.DefaultClient`.
	HTTPClient *http.Client
}