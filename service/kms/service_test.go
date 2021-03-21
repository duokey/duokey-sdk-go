package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/duokey/duokey-sdk-go/duokey"
	"github.com/duokey/duokey-sdk-go/duokey/client"
	"github.com/duokey/duokey-sdk-go/duokey/credentials"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

const (
	encryptRoute = "/api/services/app/Keys/CreateEncryptRequest"
	decryptRoute = "/api/services/app/Keys/CreateDecryptRequest"
)

func mockDecrypt(body []byte) ([]byte, error) {

	var jsonData DecryptInput

	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&jsonData); err != nil {
		return nil, err
	}

	maxLen := base64.StdEncoding.DecodedLen(len(jsonData.Payload))
	b64decoded := make([]byte, maxLen)

	len, err := base64.StdEncoding.Decode(b64decoded, jsonData.Payload)
	if err != nil {
		return nil, err
	}

	if len < maxLen {
		b64decoded = b64decoded[:len]
	}

	output := DecryptOutput{
		Success: true,
		Result: struct {
			KeyID     string `json:"keyid"`
			Algorithm string `json:"algorithm"`
			Payload   []byte `json:"payload"`
			ID        uint32 `json:"id"`
		}{
			KeyID:   jsonData.KeyID,
			Payload: b64decoded,
		},
	}

	reply := &bytes.Buffer{}
	err = json.NewEncoder(reply).Encode(output)
	return reply.Bytes(), err
}

func mockEncrypt(body []byte) ([]byte, error) {

	var jsonData EncryptInput

	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&jsonData); err != nil {
		return nil, err
	}

	b64encoded := make([]byte, base64.StdEncoding.EncodedLen(len(jsonData.Payload)))
	base64.StdEncoding.Encode(b64encoded, jsonData.Payload)

	output := EncryptOutput{
		Success: true,
		Result: struct {
			KeyID     string `json:"keyid"`
			Algorithm string `json:"algorithm"`
			Payload   []byte `json:"payload"`
			ID        uint32 `json:"id"`
		}{
			KeyID:   jsonData.KeyID,
			Payload: b64encoded,
		},
	}

	reply := &bytes.Buffer{}
	err := json.NewEncoder(reply).Encode(output)
	return reply.Bytes(), err
}

func newClientWithMockServer(credentials credentials.Config, endpoints Endpoints, httpClient *http.Client) *KMS {
	config := duokey.Config{
		Credentials: credentials,
		HTTPClient:  httpClient,
	}
	client := client.Client{Config: config}

	return &KMS{Endpoints: &endpoints, Client: &client}
}

func TestEncrypt(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload []byte
		var err error
		var body []byte

		if payload, err = ioutil.ReadAll(r.Body); err != nil {
			t.Fail()
		}

		switch r.RequestURI {
		case encryptRoute:
			if body, err = mockEncrypt(payload); err != nil {
				t.Fail()
			}
		case decryptRoute:
			if body, err = mockDecrypt(payload); err != nil {
				t.Fail()
			}
		default:
			t.Fail()
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer mockServer.Close()

	endpoints := Endpoints{
		BaseURL:      mockServer.URL,
		EncryptRoute: encryptRoute,
		DecryptRoute: decryptRoute,
	}

	credentials := credentials.Config{
		Issuer:       endpoints.BaseURL,
		ClientID:     "client",
		ClientSecret: uuid.New().String(),
		UserName:     "jane.doe",
		Password:     "tooManyS3cr3ts!",
		Scope:        "key",
		TenantID:     1,
	}

	kmsClient := newClientWithMockServer(credentials, endpoints, mockServer.Client())

	eInput := &EncryptInput{
		KeyID:   uuid.New().String(),
		VaultID: uuid.New().String(),
		Payload: []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."),
	}

	eOutput, err := kmsClient.Encrypt(eInput)
	if err != nil {
		t.Fail()
	}

	dInput := &DecryptInput{
		KeyID:   eOutput.Result.KeyID,
		VaultID: eInput.VaultID,
		Payload: eOutput.Result.Payload,
	}

	dOutput, err := kmsClient.Decrypt(dInput)
	if err != nil {
		t.Fail()
	}

	assert.Equal(t, eInput.Payload, dOutput.Result.Payload, "The two plaintexts should be the same.")
}

func TestEncryptWithTimeout(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Millisecond*10))
	defer cancel()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		time.Sleep(1 * time.Second)

		output := EncryptOutput{
			Success: false,
		}

		reply := &bytes.Buffer{}
		if err := json.NewEncoder(reply).Encode(output); err != nil {
			t.Fail()
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(reply.Bytes())
	}))
	defer mockServer.Close()

	endpoints := Endpoints{
		BaseURL:      mockServer.URL,
		EncryptRoute: encryptRoute,
		DecryptRoute: decryptRoute,
	}

	credentials := credentials.Config{
		Issuer:       endpoints.BaseURL,
		ClientID:     "client",
		ClientSecret: uuid.New().String(),
		UserName:     "jane.doe",
		Password:     "tooManyS3cr3ts!",
		Scope:        "key",
		TenantID:     1,
	}

	eInput := &EncryptInput{
		KeyID:   uuid.New().String(),
		VaultID: uuid.New().String(),
		Payload: []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."),
	}

	kmsClient := newClientWithMockServer(credentials, endpoints, mockServer.Client())

	_, err := kmsClient.EncryptWithContext(ctx, eInput)
	if err != nil {
		msg := err.Error()
		assert.Contains(t, msg, "context deadline exceeded", "a timeout was expected")
	} else {
		t.Fail()
	}
}
