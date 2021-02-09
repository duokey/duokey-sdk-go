package kms

import (
	_ "encoding/json"
	"github.com/duokey/duokey-sdk/duokey"
)

type EncryptRequest struct {
	Plaintext Blob
}

type EncryptResponse struct {
	
}