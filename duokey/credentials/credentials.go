package credentials

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/duokey/duokey-sdk-go/duokey"
	"golang.org/x/oauth2"
)

// DuoKeyTransport ...
type DuoKeyTransport struct {
	TenantID uint32
}

// RoundTrip ...
func (t *DuoKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Abp.TenantId", fmt.Sprint(t.TenantID))
	return http.DefaultTransport.RoundTrip(req)
}

// GetOauth2Config reads the token and authorization URLs from a discovery document
func GetOauth2Config(config duokey.Config) (*oauth2.Config, error) {
	provider, err := oidc.NewProvider(context.Background(), config.Issuer)
	if err != nil {
		return nil, err
	}

	conf := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Scopes:       []string{config.Scope},
		Endpoint: oauth2.Endpoint{
			AuthURL:  provider.Endpoint().AuthURL,
			TokenURL: provider.Endpoint().TokenURL,
		},
	}

	return conf, nil
}
