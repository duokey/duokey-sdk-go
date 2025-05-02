package duokey

import (
	"net/http"
	"time"

	"github.com/duokey/duokey-sdk-go/duokey/credentials"
	"golang.org/x/oauth2"
)

// Config stores the configuration of a DuoKey client: credentials needed to
// get an access token and http client.
type Config struct {
	Credentials       credentials.Config
	HTTPClient        *http.Client
	Logger            Logger
	Token             *oauth2.Token // store the token to check its validity before each call and manage expiration
	OAuth2Config      *oauth2.Config
	CheckTokenTimeOut time.Duration // the timeout for the internal checkToken() operation and the similar AuthenticateUser() operation
}
