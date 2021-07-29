package credentials

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config stores the user's credentials
type Config struct {
	Issuer         string `mapstructure:"issuer"` // URL identifier for the service
	AppID          string `mapstructure:"app-id"`
	ClientID       string `mapstructure:"client-id"`
	ClientSecret   string `mapstructure:"client-secret"`
	UserName       string `mapstructure:"username"`
	Password       string `mapstructure:"password"`
	Scope          string `mapstructure:"scope"`
	HeaderTenantID string `mapstructure:"header-tenant-id"`
	TenantID       uint32 `mapstructure:"tenant-id"`
}

// GetOauth2Config reads the token and authorization URLs from a discovery document
func GetOauth2Config(config Config) (*oauth2.Config, error) {
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
