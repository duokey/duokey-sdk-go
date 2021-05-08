package duokey

import (
	"net/http"

	"github.com/duokey/duokey-sdk-go/duokey/credentials"
)

// Config stores the configuration of a DuoKey client: credentials needed to 
// get an access token and http client.
type Config struct {
	Credentials credentials.Config
	HTTPClient  *http.Client

	Logger Logger
}
