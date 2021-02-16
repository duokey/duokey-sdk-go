package duokey

import (
	"net/http"

	"github.com/duokey/duokey-sdk-go/duokey/restapi"
	"github.com/duokey/duokey-sdk-go/duokey/credentials"
)

// Config stores the configuration of a DuoKey client.
type Config struct {
	Credentials credentials.Config
	Routes restapi.Config
	HTTPClient *http.Client
}