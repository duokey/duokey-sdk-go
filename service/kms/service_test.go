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
	encryptRoute        = "/api/services/app/Keys/CreateEncryptRequest"
	decryptRoute        = "/api/services/app/Keys/CreateDecryptRequest"
	getKeyByNameRoute   = "/api/services/app/Keys/GetKeyByName"
	getKeyByIdRoute     = "/api/services/app/Keys/GetKeyId"
	createKeyRoute      = "/api/services/app/Keys/CreateKeyRequest"
	deleteKeyRoute      = "/api/services/app/Keys/Delete"
	csrImportRoute      = "/api/services/app/CertificateRequests/ImportCertificateCSR"
	csrStatusRoute      = "/api/services/app/CertificateRequests/CertificateRequestStatus"
	getSignatureCARoute = "/api/services/app/SCEP/GetSignatureCAForScepServer"

	oauthGetTokenURL = "/connect/token"
	// Constants for tests
	// Currently those constant allow to define if a call will succeed or fail
	// They are thus passed as parameters for the call to the sdk, and used by the mocked routes to answer the request
	//
	// existingName/nonexistingName used for key names, for CSR common name, etc.
	existingName    = "existingName"
	nonexistingName = "unexistingName"
	// existingUserPWD/nonexistingUserPWD used for user authentification
	existingUserPWD    = "existingUserPWD"
	nonexistingUserPWD = "nonexistingUserPWD"
	// existingId/nonexistingId are GUID used for keyId, ScepId, etc.
	existingGuidId    = "c2d3e6e9-7f47-4b9b-92d4-91e6c8b7e3f8"
	nonexistingGuidId = "f84c0b47-9df8-49e4-94ae-3f6fdc3e13f5"
	// PEM for CSRImport operations
	// The cockpit should accept the base64 value only, or the base64 value decorated with header/footer
	// However, for tests, I do not need a real PEM but only a way to identify and simulate a valid or invalid PEM
	validPEM   = "thisIsAFakeValidPEM"
	invalidPEM = "thisIsAFakeInvalidPEM"
)

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

// mockCreateKey() simulates a CreateKey operation
// Success if AES+128, otherwise HTTP Error 500
func mockCreateKey(body []byte) ([]byte, error) {
	var jsonData CreateKeyInput

	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&jsonData); err != nil {
		return nil, err
	}

	if jsonData.KeyType != "AES 128" || jsonData.KeySize != 128 {
		return nil, errors.New("Server Internal error")
	}

	output := SuccessOutput{
		Success: true,
	}

	reply := &bytes.Buffer{}
	err := json.NewEncoder(reply).Encode(output)
	return reply.Bytes(), err
}

// mockDeleteKey() simulates a key deletion, success if the id is existingGuidId otherwise HTTP Error 500
func mockDeleteKey(body []byte) ([]byte, error) {
	var jsonData DeletekeyKeyInput

	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&jsonData); err != nil {
		return nil, err
	}

	if jsonData.Id != existingGuidId {
		return nil, errors.New("Server Internal error")
	}

	output := SuccessOutput{
		Success: true,
	}

	reply := &bytes.Buffer{}
	err := json.NewEncoder(reply).Encode(output)
	return reply.Bytes(), err
}

// mockCSRImport() CSRImport does a 500 if the PEM is invalid or if the CSR already exists
// here just do a HTTP Error 500 if invalid
func mockCSRImport(body []byte) ([]byte, error) {
	var jsonData CSRImportInput
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&jsonData); err != nil {
		return nil, err
	}

	if jsonData.CSR == invalidPEM {
		return nil, errors.New("Server Internal error")
	}

	output := CSRImportOutput{
		Success: true,
	}

	reply := &bytes.Buffer{}
	err := json.NewEncoder(reply).Encode(output)
	return reply.Bytes(), err
}

// mockCSRStatus() should not return a 500 if CSR not found, but a StatusRequest with:
//
//	Success:true
//	Status:NotFound
//	Certificate:
//
// If existingName then return status "Pending"
func mockCSRStatus(body []byte) ([]byte, error) {
	var jsonData CSRStatusInput
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&jsonData); err != nil {
		return nil, err
	}

	output := CSRStatusOutput{
		Success: true,
	}

	if jsonData.CommonName == existingName {
		output.Result.Status = "Pending"
	} else {
		output.Result.Status = "NotFound"
	}

	reply := &bytes.Buffer{}
	err := json.NewEncoder(reply).Encode(output)
	return reply.Bytes(), err
}

// mockGetToken() if nonexistingUserPWD -> return an error
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

// mockGetKeyByName()
// The cockpit currently sends a http error 500 when a key is not found
func mockGetKeyByName(name string) ([]byte, error) {
	var output GetKeyOutput

	if name == existingName {
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

// The cockpit currently sends a http error 500 when a key is not found
func mockGetKeyById(keyId string) ([]byte, error) {
	var output GetKeyOutput

	if keyId == existingGuidId {
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

// The cockpit currently sends a http error 500 when the scep App is not found
func mockGetSignatureCA(scepExternalId string) ([]byte, error) {
	var output GetSignatureCAOutput

	if scepExternalId == existingGuidId {
		// In case of success, the 'result' field should contain the certificates signature chain, but this is not tested currently
		output = GetSignatureCAOutput{
			Success: true,
			Result:  "dummyValueInsteadOfCertificatesChain",
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

		// When calling Get routes as GetKeyByName, RequestURI contains the parameters as well
		// Therefor parse the RequestURI to get the Path only and know which route is called
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
		case createKeyRoute:
			if payload, err = ioutil.ReadAll(r.Body); err != nil {
				t.Fail()
			}

			if body, err = mockCreateKey(payload); err != nil {
				// The cockpit returns a 500 when create key failed
				http.Error(w, "Internal Server error - expected when key not found", http.StatusInternalServerError)
			}
		case deleteKeyRoute:
			if payload, err = ioutil.ReadAll(r.Body); err != nil {
				t.Fail()
			}

			if body, err = mockDeleteKey(payload); err != nil {
				// The cockpit returns a 500 when delete key failed because key ID not found
				http.Error(w, "Internal Server error - expected when key not found", http.StatusInternalServerError)
			}
		case getKeyByNameRoute:
			// Get query with "name" parameter
			query := r.URL.Query()
			if body, err = mockGetKeyByName(query.Get("name")); err != nil {
				// The cockpit returns a 500 when the key is not found
				// This might be a bug, but it is the current behavior
				http.Error(w, "Internal Server error - expected when key not found", http.StatusInternalServerError)
			}
		case getKeyByIdRoute:
			// Get query with "externalId" parameter
			query := r.URL.Query()
			if body, err = mockGetKeyById(query.Get("externalId")); err != nil {
				// The cockpit returns a 500 when the key is not found
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
		case getSignatureCARoute:
			// Get query with "scepExternalId" parameter
			query := r.URL.Query()
			if body, err = mockGetSignatureCA(query.Get("scepExternalId")); err != nil {
				// The cockpit returns a 500 when the scep App is not found
				http.Error(w, "Internal Server error - An internal error occurred during your request!", http.StatusInternalServerError)
			}
		case csrImportRoute:
			if payload, err = ioutil.ReadAll(r.Body); err != nil {
				t.Fail()
			}

			if body, err = mockCSRImport(payload); err != nil {
				// The cockpit returns a 500 when the CSR already exists or the PEM format is invalid
				// The message is different, but not replicated here.
				// - Existing CSR:
				// 	{"result":null,"targetUrl":null,"success":false,"error":{"code":0,"message":"C=US,O=scep-client,OU=MDM,CN=commonName16092024 is already exist. Please use another."
				// - Invalid CSR:
				// 	{"result":null,"targetUrl":null,"success":false,"error":{"code":0,"message":"Invalid certificate request format. You are trying to import a certificate in the certificate request module."
				http.Error(w, "Internal Server error - CSR Import Error", http.StatusInternalServerError)
			}
		case csrStatusRoute:
			if payload, err = ioutil.ReadAll(r.Body); err != nil {
				t.Fail()
			}

			if body, err = mockCSRStatus(payload); err != nil {
				http.Error(w, "Internal Server error - Unexpected error", http.StatusInternalServerError)
			}
		default:
			t.Fail()
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))

	endpoints := Endpoints{
		BaseURL:             mockServer.URL,
		EncryptRoute:        encryptRoute,
		DecryptRoute:        decryptRoute,
		GetKeyByNameRoute:   getKeyByNameRoute,
		GetKeyIdRoute:       getKeyByIdRoute,
		CreateKeyRoute:      createKeyRoute,
		DeleteKeyRoute:      deleteKeyRoute,
		CSRImportRoute:      csrImportRoute,
		CSRStatusRoute:      csrStatusRoute,
		GetSignatureCARoute: getSignatureCARoute,
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

// mockGetKeyByName() of newClientWithStandardMockServer() relies on the predefined key names to return a found or not found key
func TestGetKeyByName(t *testing.T) {
	testCases := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{name: "Existing key",
			config: map[string]string{
				"key_name": existingName,
			},
			wantErr: false,
		},
		{name: "Nonexisting key",
			config: map[string]string{
				"key_name": nonexistingName,
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
			validateErrorAndSuccess(t, testCase.wantErr, eOutput.Success, err)
		})
	}
}

// mockGetKeyById() of newClientWithStandardMockServer() relies on the predefined key Ids to return a found or not found key
func TestGetKeyById(t *testing.T) {
	testCases := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{name: "Existing key",
			config: map[string]string{
				"key_id": existingGuidId,
			},
			wantErr: false,
		},
		{name: "Nonexisting key",
			config: map[string]string{
				"key_id": nonexistingGuidId,
			},
			wantErr: true,
		},
	}

	kmsClient, mockServer := newClientWithStandardMockServer(t)
	defer mockServer.Close()

	for _, testCase := range testCases {

		t.Run(testCase.name, func(t *testing.T) {
			getKeyInput := &GetKeyIdInput{
				ExternalID: testCase.config["key_id"],
			}

			eOutput, err := kmsClient.GetKeyId(getKeyInput)
			validateErrorAndSuccess(t, testCase.wantErr, eOutput.Success, err)
		})
	}
}

// mockCreateKey of newClientWithStandardMockServer() returns true for AES 128, otherwise error 500
func TestCreateKey(t *testing.T) {
	testCases := []struct {
		name    string
		config  map[string]int
		wantErr bool
	}{
		{name: "Correct key",
			config: map[string]int{
				"key_size": 128,
			},
			wantErr: false,
		},
		{name: "Wrong key",
			config: map[string]int{
				"key_size": 130,
			},
			wantErr: true,
		},
	}

	kmsClient, mockServer := newClientWithStandardMockServer(t)
	defer mockServer.Close()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			eInput := &CreateKeyInput{
				VaultID:          "1",
				KeyName:          "dummyKeyName",
				KeyType:          "AES 128",
				KeySize:          testCase.config["key_size"],
				IsEnabled:        true,
				State:            1, // 0 = preActive, 1=active
				Id:               "",
				IsDecrypt:        true,
				IsEncrypt:        true,
				IsAuditLogEnable: true,
				PublishPublicKey: false,
				Reason:           0,
			}

			eOutput, err := kmsClient.CreateKey(eInput)
			validateErrorAndSuccess(t, testCase.wantErr, eOutput.Success, err)
		})
	}
}

// mockDeleteKey of newClientWithStandardMockServer() returns success for existingKeyId, http error 500 otherwise
func TestDeleteKey(t *testing.T) {
	testCases := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{name: "Correct key",
			config: map[string]string{
				"key_id": existingGuidId,
			},
			wantErr: false,
		},
		{name: "Wrong key",
			config: map[string]string{
				"key_id": nonexistingGuidId,
			},
			wantErr: true,
		},
	}

	kmsClient, mockServer := newClientWithStandardMockServer(t)
	defer mockServer.Close()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			deleteKeyInput := &DeletekeyKeyInput{
				Id: testCase.config["key_id"],
			}

			eOutput, err := kmsClient.DeleteKey(deleteKeyInput)
			validateErrorAndSuccess(t, testCase.wantErr, eOutput.Success, err)
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

// mockGetSignatureCA() of newClientWithStandardMockServer() relies on the predefined app Id to return a success or http 500 when not found
func TestGetSignatureCA(t *testing.T) {
	testCases := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{name: "Existing App",
			config: map[string]string{
				"app_id": existingGuidId,
			},
			wantErr: false,
		},
		{name: "Nonexisting App",
			config: map[string]string{
				"app_id": nonexistingGuidId,
			},
			wantErr: true,
		},
	}

	kmsClient, mockServer := newClientWithStandardMockServer(t)
	defer mockServer.Close()

	for _, testCase := range testCases {

		t.Run(testCase.name, func(t *testing.T) {
			eInput := &GetSignatureCAInput{
				ScepExternalId: testCase.config["app_id"],
			}

			eOutput, err := kmsClient.GetSignatureCA(eInput)
			validateErrorAndSuccess(t, testCase.wantErr, eOutput.Success, err)
		})
	}
}

// mockCSRImport() of newClientWithStandardMockServer() relies on the predefined validPEM and invalidPEM a success or http 500 when not found
// 500 is returned by Cockpit if the CSR already exists, or if the PEM is invalid: both are simulated with 'invalidPEM'
func TestCSRImport(t *testing.T) {
	testCases := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{name: "Valid CSR PEM",
			config: map[string]string{
				"csr_pem": validPEM,
			},
			wantErr: false,
		},
		{name: "Invalid CSR PEM",
			config: map[string]string{
				"csr_pem": invalidPEM,
			},
			wantErr: true,
		},
	}

	kmsClient, mockServer := newClientWithStandardMockServer(t)
	defer mockServer.Close()

	for _, testCase := range testCases {

		t.Run(testCase.name, func(t *testing.T) {
			// Note: Context can contain a "TransactionID" that is optional
			// But for the tests, the Context values are currently not tested
			eInput := &CSRImportInput{
				CSR: testCase.config["csr_pem"],
				Context: Context{
					AppID: "dummyAppID",
				},
			}

			eOutput, err := kmsClient.CSRImport(eInput)

			validateErrorAndSuccess(t, testCase.wantErr, eOutput.Success, err)
		})
	}
}

// The Cockpit do not retun a 500, if not found, but Success:true and a different Status.
// The mock returns Status "Pending" if found, "NotFound" otherwise
func TestCSRStatus(t *testing.T) {
	testCases := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{name: "Existing CSR",
			config: map[string]string{
				"csr_cn":          existingName,
				"expected_status": "Pending",
			},
			wantErr: false,
		},
		{name: "Invalid CSR",
			config: map[string]string{
				"csr_cn":          nonexistingName,
				"expected_status": "NotFound",
			},
			wantErr: false,
		},
	}

	kmsClient, mockServer := newClientWithStandardMockServer(t)
	defer mockServer.Close()

	for _, testCase := range testCases {

		t.Run(testCase.name, func(t *testing.T) {
			// Note: "TransactionID" that is optional
			eInputStatus := &CSRStatusInput{
				CommonName: testCase.config["csr_cn"],
			}

			eOutput, err := kmsClient.CSRStatus(eInputStatus)

			// In both cases, there should be no error and success = true
			validateErrorAndSuccess(t, testCase.wantErr, eOutput.Success, err)
			// For the existing csr status will be "Pending", but "NotFound" for the nonexistingName
			if eOutput.Result.Status != testCase.config["expected_status"] {
				t.Errorf("Expected status '%v', but received '%v'", testCase.config["expected_status"], eOutput.Result.Status)
			}
		})
	}
}

// A test validation where the expected result of the test is either an error, or a success=true
func validateErrorAndSuccess(t *testing.T, wantErr bool, success bool, err error) {
	if wantErr {
		if err == nil {
			t.Error("Error expected")
		}
	} else {
		if err != nil {
			t.Errorf("Unexpected error: %v", err.Error())
		}

		if success != true {
			t.Error("output.Success == false, but true expected")
		}
	}
}
