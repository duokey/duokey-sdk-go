package kms

import (
	"context"
	"net/http"

	"github.com/duokey/duokey-sdk-go/duokey/request"
	"github.com/google/go-querystring/query"
)

// GetAllKeys
const opGetAllKeys = "GetAllKeys"

type GetAllKeysInput struct {
	Filter            string `url:"Filter,omitempty"`
	NameFilter        string `url:"NameFilter,omitempty"`
	StateFilter       int    `url:"StateFilter,omitempty"`
	VaultNameFilter   string `url:"VaultNameFilter,omitempty"`
	ExternalId        string `url:"ExternalId,omitempty"`
	VaultId           string `url:"VaultId,omitempty"`
	Sorting           string `url:"Sorting,omitempty"`
	SkipCount         int    `url:"SkipCount,omitempty"`
	MaxResultCount    int    `url:"MaxResultCount,omitempty"`
}

type GetAllKeysOutput struct {
	Result struct {
		Items      []GetKeyForViewDto `json:"items"`
		TotalCount int                `json:"totalCount"`
	} `json:"result"`
	TargetURL           *string `json:"targetUrl"`
	Success             bool    `json:"success"`
	Error               *string `json:"error"`
	UnauthorizedRequest bool    `json:"unAuthorizedRequest"`
	ABP                 bool    `json:"__abp"`
}

type GetKeyForViewDto struct {
	Key       KeySummaryDto `json:"key"`
	VaultName string        `json:"vaultName"`
	VaultType int           `json:"vaultType"`
}

type KeySummaryDto struct {
	Name       string `json:"name"`
	Size       int    `json:"size"`
	PublicKey  string `json:"publicKey"`
	IsEnabled  bool   `json:"isEnabled"`
	State      int    `json:"state"`
	ExternalId string `json:"externalId"`
	IsDecrypt  bool   `json:"isDecrypt"`
	IsEncrypt  bool   `json:"isEncrypt"`
	IsWrap     bool   `json:"isWrap"`
	IsUnwrap   bool   `json:"isUnwrap"`
	IsSign     bool   `json:"isSign"`
	IsVerify   bool   `json:"isVerify"`
	Type       string `json:"type"`
	VaultId    string `json:"vaultId"`
	Id         string `json:"id"`
}

func (k *KMS) GetAllKeys(input *GetAllKeysInput) (*GetAllKeysOutput, error) {
	req, out := k.getAllKeysRequest(input)

	return out, k.SendRequestWithTokenUpdate(req)
}

func (k *KMS) GetAllKeysWithContext(ctx context.Context, input *GetAllKeysInput) (*GetAllKeysOutput, error) {
	req, out := k.getAllKeysRequest(input)
	req.SetContext(ctx)

	return out, k.SendRequestWithTokenUpdate(req)
}

func (k *KMS) getAllKeysRequest(input *GetAllKeysInput) (req *request.Request, output *GetAllKeysOutput) {

	// This is used to get query parameter format from struct
	// queryParams.Encode() will convert it into string
	queryParams, _ := query.Values(input)

	op := &request.Operation{
		Name:        opGetAllKeys,
		HTTPMethod:  http.MethodGet,
		BaseURL:     k.Endpoints.BaseURL,
		Route:       k.Endpoints.GetAllKeysRoute,
		QueryParams: queryParams.Encode(),
	}

	if input == nil {
		input = &GetAllKeysInput{}
	}

	output = &GetAllKeysOutput{}
	req = k.NewRequest(op, input, output)

	return
}
