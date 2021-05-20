package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
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
			KeyID     string `json:"keyid" validate:"nonzero"`
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
			KeyID     string `json:"keyid" validate:"nonzero"`
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

func TestInputValidation(t *testing.T) {

}

func TestEncryptDecrypt(t *testing.T) {

	const headerTenantID = "Abp.TenantId"

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload []byte
		var err error
		var body []byte

		tenantID := r.Header.Get(headerTenantID)
		if tenantID == "" {
			t.Error("Tenant ID not found")
		}
		_, err = strconv.Atoi(tenantID)
		if err != nil {
			t.Error("TenantID: bad format")
		}

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
		Issuer:         endpoints.BaseURL,
		ClientID:       "client",
		ClientSecret:   uuid.New().String(),
		UserName:       "jane.doe",
		Password:       "tooManyS3cr3ts!",
		Scope:          "key",
		HeaderTenantID: headerTenantID,
		TenantID:       1,
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

	testCases := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{name: "Responsive server",
			config: map[string]string{
				"context_timeout":      "10000", // All durations are in milliseconds
				"server_response_time": "100",
			},
			wantErr: false,
		},
		{name: "Unresponsive server",
			config: map[string]string{
				"context_timeout":      "10",
				"server_response_time": "1000",
			},
			wantErr: true, // Timeout expected
		},
	}

	for _, testCase := range testCases {

		t.Run(testCase.name, func(t *testing.T) {

			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var payload []byte
				var err error
				var body []byte

				serverResponseTime, err := strconv.Atoi(testCase.config["server_response_time"])
				if err != nil {
					t.Error("Server response time: bad format")
				}

				time.Sleep(time.Duration(serverResponseTime) * time.Millisecond)

				if payload, err = ioutil.ReadAll(r.Body); err != nil {
					t.Fail()
				}

				switch r.RequestURI {
				case encryptRoute:
					if body, err = mockEncrypt(payload); err != nil {
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
				Issuer:         endpoints.BaseURL,
				ClientID:       "client",
				ClientSecret:   uuid.New().String(),
				UserName:       "jane.doe",
				Password:       "tooManyS3cr3ts!",
				Scope:          "key",
				HeaderTenantID: "Abp.TenantId",
				TenantID:       1,
			}

			eInput := &EncryptInput{
				KeyID:   uuid.New().String(),
				VaultID: uuid.New().String(),
				Payload: []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."),
			}

			kmsClient := newClientWithMockServer(credentials, endpoints, mockServer.Client())

			ctxTimeout, err := strconv.Atoi(testCase.config["context_timeout"])
			if err != nil {
				t.Error("Context with timeout: bad format")
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Duration(ctxTimeout)*time.Millisecond))
			defer cancel()

			eOutput, err := kmsClient.EncryptWithContext(ctx, eInput)

			if testCase.wantErr {
				if err != nil {
					msg := err.Error()
					assert.Contains(t, msg, "context deadline exceeded", "a timeout was expected")
				} else {
					t.Error("Timeout expected")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %w", err)
				} else {
					assert.Equal(t, []byte("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEu"), eOutput.Result.Payload)
				}
			}
		})
	}
}
