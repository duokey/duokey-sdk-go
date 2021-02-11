package duokey

import (
	"net/http"
)

// Config ...
type Config struct {
	// TenantID must be copied into the header of each request
	TenantID uint32
	Endpoint string

	// TODO: access token
	
	// The HTTP client to use when sending requests. Defaults to
	// `http.DefaultClient`.
	HTTPClient *http.Client
}