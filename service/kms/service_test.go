package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/duokey/duokey-sdk-go/duokey"
	"github.com/duokey/duokey-sdk-go/duokey/client"
	"github.com/duokey/duokey-sdk-go/duokey/credentials"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

const (
	// Routes
	encryptRoute      = "/api/services/app/Keys/CreateEncryptRequest"
	decryptRoute      = "/api/services/app/Keys/CreateDecryptRequest"
	getKeyByNameRoute = "/api/services/app/Keys/GetKeyByName"
	oauthGetTokenURL  = "/connect/token"
	// Constants for tests
	existingKeyName    = "existingKeyName"
	nonexistingKeyName = "unexistingKeyName"
	existingUserPWD    = "existingUserPWD"
	nonexistingUserPWD = "nonexistingUserPWD"
)

// "DUOKEY_CREATEKEY_ROUTE": "/api/services/app/Keys/CreateKeyRequest",
// "DUOKEY_DELETEKEY_ROUTE": "/api/services/app/Keys/Delete",
// "DUOKEY_ENCRYPT_ROUTE": "/api/services/app/Keys/CreateEncryptRequest",
// "DUOKEY_DECRYPT_ROUTE": "/api/services/app/Keys/CreateDecryptRequest",
// "DUOKEY_IMPORT_ROUTE": "/api/services/app/Keys/Import",
// "DUOKEY_GETKEYID_ROUTE": "/api/services/app/Keys/GetKeyId",
// "DUOKEY_GETKEYBYNAME_ROUTE": "/api/services/app/Keys/GetKeyByName",
// "DUOKEY_CSRIMPORT_ROUTE": "/api/services/app/CertificateRequests/ImportCertificateCSR",
// "DUOKEY_CSRSTATUS_ROUTE": "/api/services/app/CertificateRequests/CertificateRequestStatus",
// "DUOKEY_GETSIGNATURECA_ROUTE": "/api/services/app/SCEP/GetSignatureCAForScepServer"

func mockDecrypt(body []byte) ([]byte, error) {

	var jsonData DecryptInput

	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&jsonData); err != nil {
		return nil, err
	}

	/*
		maxLen := base64.StdEncoding.DecodedLen(len(jsonData.Payload))
		b64decoded := make([]byte, maxLen)

		len, err := base64.StdEncoding.Decode(b64decoded, jsonData.Payload)
		if err != nil {
			return nil, err
		}

		if len < maxLen {
			b64decoded = b64decoded[:len]
		}
	*/

	output := DecryptOutput{
		Success: true,
		Result: struct {
			KeyID     string `json:"keyid" validate:"nonzero"`
			Algorithm string `json:"algorithm"`
			Payload   []byte `json:"payload" validate:"nonzero"`
			ID        uint32 `json:"id"`
		}{
			KeyID:   jsonData.KeyID,
			Payload: []byte(jsonData.Payload),
		},
	}

	reply := &bytes.Buffer{}
	err := json.NewEncoder(reply).Encode(output)
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
			KeyID            string `json:"keyid" validate:"nonzero"`
			Algorithm        string `json:"algorithm"`
			EncryptedPayload string `json:"encryptedPayload" validate:"nonzero"`
			ID               uint32 `json:"id"`
			Iv               string `json:"initializationVector"`
			Tag              string `json:"messageAuthenticationCode"`
		}{
			KeyID:            jsonData.KeyID,
			EncryptedPayload: string(jsonData.Payload),
		},
	}

	reply := &bytes.Buffer{}
	err := json.NewEncoder(reply).Encode(output)
	return reply.Bytes(), err
}

// if nonexistingUserPWD -> return an error
// otherwise return a dummy token that will pass the tests:
//
//	Token.Valid() is called (checking that AccessToken is not empty and token not expired)
//	and also that token_type is "Bearer"
func mockGetToken(user string, password string) ([]byte, error) {
	if password == nonexistingUserPWD {
		return nil, errors.New("Server Internal error - user/password mismatch")
	} else {
		response := map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		reply := &bytes.Buffer{}
		err := json.NewEncoder(reply).Encode(response)
		return reply.Bytes(), err
	}
}

// The cockpit currently trickers a http error 500 when a key is not found
func mockGetKeyByName(name string) ([]byte, error) {
	var output GetKeyOutput

	if name == existingKeyName {
		output = GetKeyOutput{
			Success: true,
		}
	} else {
		return nil, errors.New("Server Internal error")
	}

	reply := &bytes.Buffer{}
	err := json.NewEncoder(reply).Encode(output)
	return reply.Bytes(), err
}

func newClientWithMockServer(credentials credentials.Config, endpoints Endpoints, httpClient *http.Client) *KMS {
	// Prepare a dummy oauth2 config + token
	// This is enough as currently the following checks are done:
	//	if config.OAuth2Config is not nil, and config.Token exists
	// 		-> then a simple config.Token.Valid() is called (checking that AccessToken is not empty and token not expired)
	oauth2Config := &oauth2.Config{
		ClientID:     "dummyClientID",
		ClientSecret: "dummyClientSecret",
	}

	token := &oauth2.Token{
		AccessToken:  "mock-access-token",
		TokenType:    "Bearer",
		RefreshToken: "mock-refresh-token",
		Expiry:       time.Now().Add(1 * time.Hour), // make sure it's in the future
	}

	config := duokey.Config{
		Credentials:  credentials,
		HTTPClient:   httpClient,
		Logger:       duokey.NewDefaultLogger(),
		OAuth2Config: oauth2Config,
		Token:        token,
	}

	client := client.Client{Config: config}

	return &KMS{Endpoints: &endpoints, Client: &client}
}

// newClientWithStandardMockServer() instanciate a standard mock server calling the defined mock routes
// the kms client and the mock server are both returned -> the mock server will have to be closed
func newClientWithStandardMockServer(t *testing.T) (*KMS, *httptest.Server) {
	const headerTenantID = "Abp.TenantId"

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload []byte
		var err error
		var body []byte

		tenantID := r.Header.Get(headerTenantID)
		if tenantID == "" {
			t.Error("newClientWithStandardMockServer() - Tenant ID not found")
		}
		_, err = strconv.Atoi(tenantID)
		if err != nil {
			t.Error("newClientWithStandardMockServer() - TenantID: bad format")
		}

		// getKeyByName is a Get with parameters
		parsedURL, err := url.Parse(r.RequestURI)
		if err != nil {
			t.Errorf("newClientWithStandardMockServer() url.parse() error: %v", err.Error())
		}

		switch parsedURL.Path {
		case encryptRoute:
			if payload, err = ioutil.ReadAll(r.Body); err != nil {
				t.Fail()
			}

			if body, err = mockEncrypt(payload); err != nil {
				t.Fail()
			}
		case decryptRoute:
			if payload, err = ioutil.ReadAll(r.Body); err != nil {
				t.Fail()
			}

			if body, err = mockDecrypt(payload); err != nil {
				t.Fail()
			}
		case getKeyByNameRoute:
			// Get query with "name" parameter
			query := r.URL.Query()
			if body, err = mockGetKeyByName(query.Get("name")); err != nil {
				// The cockpit returns a 500 when the key is not found
				// This might be a bug, but it is the current behavior
				http.Error(w, "Internal Server error - expected when key not found", http.StatusInternalServerError)
			}
		case oauthGetTokenURL:
			// The cockpit returns a 400 if the user/pwd do not match
			err := r.ParseForm()
			if err != nil {
				t.Fail()
			}
			username := r.FormValue("username")
			password := r.FormValue("password")

			if body, err = mockGetToken(username, password); err != nil {
				http.Error(w, "Internal Server error - User/pwd get token error", http.StatusBadRequest)
			}
		default:
			t.Fail()
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	//defer mockServer.Close()

	endpoints := Endpoints{
		BaseURL:           mockServer.URL,
		EncryptRoute:      encryptRoute,
		DecryptRoute:      decryptRoute,
		GetKeyByNameRoute: getKeyByNameRoute,
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

	// Prepare a dummy oauth2 config + token
	// This is enough as currently the following checks are done:
	//	if config.OAuth2Config is not nil, and config.Token exists
	// 		-> then a simple config.Token.Valid() is called (checking that AccessToken is not empty and token not expired)
	oauth2Config := &oauth2.Config{
		ClientID:     "dummyClientID",
		ClientSecret: "dummyClientSecret",
		Endpoint: oauth2.Endpoint{
			TokenURL: mockServer.URL + oauthGetTokenURL,
		},
	}

	token := &oauth2.Token{
		AccessToken:  "mock-access-token",
		TokenType:    "Bearer",
		RefreshToken: "mock-refresh-token",
		Expiry:       time.Now().Add(1 * time.Hour), // make sure it's in the future
	}

	config := duokey.Config{
		Credentials:  credentials,
		HTTPClient:   mockServer.Client(),
		Logger:       duokey.NewDefaultLogger(),
		OAuth2Config: oauth2Config,
		Token:        token,
	}

	client := client.Client{Config: config}

	return &KMS{Endpoints: &endpoints, Client: &client}, mockServer
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
		Payload: []byte("Lorem ipsum"),
	}

	eOutput, err := kmsClient.Encrypt(eInput)
	if err != nil {
		t.Fail()
	}

	dInput := &DecryptInput{
		KeyID:   eOutput.Result.KeyID,
		VaultID: eInput.VaultID,
		Payload: eOutput.Result.EncryptedPayload,
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
					t.Errorf("Unexpected error: " + err.Error())
				} else {
					assert.Equal(t, string(eInput.Payload), eOutput.Result.EncryptedPayload, "The two plaintexts should be the same.")
				}
			}
		})
	}
}

// mockGetKeyByName() relies on the predefined key names to return a found or not found key
func TestGetKeyByName(t *testing.T) {
	testCases := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{name: "Existing key",
			config: map[string]string{
				"key_name": existingKeyName,
			},
			wantErr: false,
		},
		{name: "Nonexisting key",
			config: map[string]string{
				"key_name": nonexistingKeyName,
			},
			wantErr: true, // Key not found expected - The cockpit currently triggers an error 500 when key not found
		},
	}

	kmsClient, mockServer := newClientWithStandardMockServer(t)
	defer mockServer.Close()

	for _, testCase := range testCases {

		t.Run(testCase.name, func(t *testing.T) {
			getKeyInput := &GetKeyByNameInput{
				Name: testCase.config["key_name"],
			}

			eOutput, err := kmsClient.GetKeyByName(getKeyInput)

			if testCase.wantErr {
				if err == nil {
					t.Error("Error expected")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: " + err.Error())
				}

				if eOutput.Success != true {
					t.Error("output.Success == false, but true expected")
				}
			}
		})
	}
}

func TestAuthenticateUser(t *testing.T) {
	testCases := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{name: "Existing user",
			config: map[string]string{
				"user_pwd": existingUserPWD,
			},
			wantErr: false,
		},
		{name: "Nonexisting user",
			config: map[string]string{
				"user_pwd": nonexistingUserPWD,
			},
			wantErr: true,
		},
	}

	kmsClient, mockServer := newClientWithStandardMockServer(t)
	defer mockServer.Close()

	for _, testCase := range testCases {

		t.Run(testCase.name, func(t *testing.T) {
			_, err := kmsClient.AuthenticateUser("aUsername", testCase.config["user_pwd"])

			if testCase.wantErr {
				if err == nil {
					t.Error("Error expected")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: " + err.Error())
				}
			}
		})
	}
}
