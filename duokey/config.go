package duokey

import (
	"net/http"

	"github.com/duokey/duokey-sdk-go/duokey/restapi"
	"github.com/duokey/duokey-sdk-go/duokey/credentials"
)

// Config stores the configuration of a DuoKey client: credentials needed to get an access token,
// customizable routes of the DuoKey REST API, and http client.  
type Config struct {
	Credentials credentials.Config
	Routes restapi.Config
	HTTPClient *http.Client
}