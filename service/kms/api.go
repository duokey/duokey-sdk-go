package kms

import (
	_ "encoding/json"
	"github.com/duokey-kms/duokey"
)

type EncryptRequest struct {
	Plaintext Blob
}

type EncryptResponse struct {
	
}