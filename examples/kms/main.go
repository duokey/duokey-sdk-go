package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/duokey/duokey-sdk-go/duokey/credentials"
	"github.com/duokey/duokey-sdk-go/service/kms"
)

var (
	// Application
	appID string

	// Credentials
	upn            string
	issuer         string
	clientID       string
	clientSecret   string
	userName       string
	password       string
	scope          string
	tenantID       uint32
	headerTenantID string

	// Encryption/decryption client
	baseURL       string
	encryptRoute  string
	decryptRoute  string
	importRoute   string
	getKeyIdRoute string

	// CSR + SCEP
	csrImportRoute string
	csrStatusRoute string
	getSignatureCA string

	// Vault and key
	vaultID string
	keyID   string
)

func timeTrack(start time.Time) {
	fmt.Printf("Operations took %s\n", time.Since(start))
}

func getConfig() {
	switch {
	case os.Getenv("DUOKEY_APP_ID") != "":
		appID = os.Getenv("DUOKEY_APP_ID")
	default:
		fmt.Println("DUOKEY_APP_ID is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_UPN") != "":
		upn = os.Getenv("DUOKEY_UPN")
	default:
		fmt.Println("DUOKEY_UPN is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_ISSUER") != "":
		issuer = os.Getenv("DUOKEY_ISSUER")
	default:
		fmt.Println("DUOKEY_ISSUER is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_CLIENT_ID") != "":
		clientID = os.Getenv("DUOKEY_CLIENT_ID")
	default:
		fmt.Println("DUOKEY_CLIENT_ID is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_CLIENT_SECRET") != "":
		clientSecret = os.Getenv("DUOKEY_CLIENT_SECRET")
	default:
		fmt.Println("DUOKEY_CLIENT_SECRET is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_USERNAME") != "":
		userName = os.Getenv("DUOKEY_USERNAME")
	default:
		fmt.Println("DUOKEY_USERNAME is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_PASSWORD") != "":
		password = os.Getenv("DUOKEY_PASSWORD")
	default:
		fmt.Println("DUOKEY_PASSWORD is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_SCOPE") != "":
		scope = os.Getenv("DUOKEY_SCOPE")
	default:
		fmt.Println("DUOKEY_SCOPE is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_HEADER_TENANT_ID") != "":
		headerTenantID = os.Getenv("DUOKEY_HEADER_TENANT_ID")
	default:
		fmt.Println("DUOKEY_HEADER_TENANT_ID is not defined")
		os.Exit(1)
	}

	var tid string

	switch {
	case os.Getenv("DUOKEY_TENANT_ID") != "":
		tid = os.Getenv("DUOKEY_TENANT_ID")
	default:
		fmt.Println("DUOKEY_TENANT_ID is not defined")
		os.Exit(1)
	}

	value, err := strconv.ParseUint(tid, 10, 32)
	if err != nil {
		fmt.Println("Tenant ID must be an uint32 value")
		os.Exit(1)
	}
	tenantID = uint32(value)

	switch {
	case os.Getenv("DUOKEY_BASE_URL") != "":
		baseURL = os.Getenv("DUOKEY_BASE_URL")
	default:
		fmt.Println("DUOKEY_BASE_URL is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_ENCRYPT_ROUTE") != "":
		encryptRoute = os.Getenv("DUOKEY_ENCRYPT_ROUTE")
	default:
		fmt.Println("DUOKEY_ENCRYPT_ROUTE is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_DECRYPT_ROUTE") != "":
		decryptRoute = os.Getenv("DUOKEY_DECRYPT_ROUTE")
	default:
		fmt.Println("DUOKEY_DECRYPT_ROUTE is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_IMPORT_ROUTE") != "":
		importRoute = os.Getenv("DUOKEY_IMPORT_ROUTE")
	default:
		fmt.Println("DUOKEY_IMPORT_ROUTE is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_GETKEYID_ROUTE") != "":
		getKeyIdRoute = os.Getenv("DUOKEY_GETKEYID_ROUTE")
	default:
		fmt.Println("DUOKEY_GETKEYID_ROUTE is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_VAULT_ID") != "":
		vaultID = os.Getenv("DUOKEY_VAULT_ID")
	default:
		fmt.Println("DUOKEY_VAULT_ID is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_KEY_ID") != "":
		keyID = os.Getenv("DUOKEY_KEY_ID")
	default:
		fmt.Println("DUOKEY_KEY_ID is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_CSRIMPORT_ROUTE") != "":
		csrImportRoute = os.Getenv("DUOKEY_CSRIMPORT_ROUTE")
	default:
		fmt.Println("DUOKEY_CSRIMPORT_ROUTE is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_CSRSTATUS_ROUTE") != "":
		csrStatusRoute = os.Getenv("DUOKEY_CSRSTATUS_ROUTE")
	default:
		fmt.Println("DUOKEY_CSRSTATUS_ROUTE is not defined")
		os.Exit(1)
	}

	switch {
	case os.Getenv("DUOKEY_GETSIGNATURECA_ROUTE") != "":
		getSignatureCA = os.Getenv("DUOKEY_GETSIGNATURECA_ROUTE")
	default:
		fmt.Println("DUOKEY_GETSIGNATURECA_ROUTE is not defined")
		os.Exit(1)
	}

}

/*
* main() with an encrypt/decrypt example + getKeyID
* The key is set in the DUOKEY_KEY_ID variable
*	This code was tested with an RSA or AES key
* For RSA operations:
*	Algorithm: "RSA-OAEP-256"
*		In former versions, was "3", used for Sepior
* For AES-GCM operations:
*	Algorithm: "AES-GCM",
*	And the Iv, received from the Encrypt operation, can be passed in the DecryptInput
 */
func main() {

	getConfig()

	credentials := credentials.Config{
		AppID:          appID,
		Issuer:         issuer,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		UserName:       userName,
		Password:       password,
		Scope:          scope,
		HeaderTenantID: headerTenantID,
		TenantID:       tenantID,
	}

	endpoints := kms.Endpoints{
		BaseURL:        baseURL,
		EncryptRoute:   encryptRoute,
		DecryptRoute:   decryptRoute,
		ImportRoute:    importRoute,
		GetKeyIdRoute:  getKeyIdRoute,
		CSRImportRoute: csrImportRoute,
		CSRStatusRoute: csrStatusRoute,
		GetSignatureCA: getSignatureCA,
	}

	vaultClient, err := kms.NewClient(credentials, endpoints)
	if err != nil {
		fmt.Println("Error:", err.Error())
		os.Exit(1)
	}

	// To run testKeysOperations(), adapt the parameters
	// For Fabian: launch.json, use the parameters "App to try the sdk with the cockpit demo (not test) - works in December 2024"
	testKeysOperations(vaultClient)
	// To run testCSROperations(), adapt the parameters
	// For Fabian: launch.json, use the parameters "App for SCEP (on cockpit-api-test) - from Pargat - August 2024"
	// testCSROperations(vaultClient)
	// testAuthenticateUser(): should be done with other credentials than the ones used by this duokey-sdk-go
	//	But here testing the functionality with the same credentials
	// testAuthenticateUser(vaultClient, credentials.UserName, credentials.Password)
	// testGetSignatureCA(vaultClient)
}

// Testing the authentication of a user with a user/pwd
func testAuthenticateUser(vaultClient *kms.KMS, username string, pwd string) {
	fmt.Println("Testing AuthenticateUser() by the cockpit - username: " + username)

	token, err := vaultClient.AuthenticateUser(username, pwd)
	if err != nil {
		fmt.Println("AuthenticateUser() failed:", err.Error())
	} else {
		if token != nil {
			fmt.Println("AuthenticateUser() succeeded, token received")
		} else {
			fmt.Println("AuthenticateUser() strange behavior: no error but no token received")
		}
	}
}

// Testing the implementation of the Cockpit's CSR Import+status operations
func testCSROperations(vaultClient *kms.KMS) {
	// The cockpit should accept the base64 value only, or the base64 value decorated with header/footer
	// But the clean call should be only with base64 value
	csrPEM := `MIICqjCCAZICAQAwTjELMAkGA1UEBhMCVVMxFDASBgNVBAoTC3NjZXAtY2xpZW50
MQwwCgYDVQQLEwNNRE0xGzAZBgNVBAMTEmNvbW1vbk5hbWUxNjA5MjAyNDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANGrH6ChMGD8t7eKkv91smuUEVE5
7im7WQLbvxR79Y9zzSLs54ehDEFEqCXMOgU7yQhJqqH8ZcE6VHnyiihCfoz1WR4h
Ta6nEzG1z0c8R13gor13IC43/U7l1i2CTkkAevfXGrFK/naqcFCc7aI+EbQRb2H7
DeBefVfKpcvGV2eW22hHCC5OAWoGCeCR1c5VVTW1DJrCnxnrLb2JxEm1QHkH0EA/
E7NfvzI4PmoIKmUv7iMLGDJtqEs6OxwsTZ4glKO3BZ56VdQk+RQroRR2jeh/d0/K
rAGlvUsmmDB27Ej65y2LLAC6Te7vNqhwNI9g/nGSM0x6/Cq/lb1vMICZl4UCAwEA
AaAXMBUGCSqGSIb3DQEJBzEIEwZzZWNyZXQwDQYJKoZIhvcNAQELBQADggEBACnZ
sA0EYOEDAiVepolIdXhfQPrjrFO0xDfv4nTKzAc6ygDXsZbEzXJBi9QfOzge25l/
sj+MlMXbJVdlIxZn0r97k40DqFZ1Twr9ch3DKaPUT8Z6lFcddGH2IG/4XmxhV0Dj
NQj+Wv04PV0or0+UlFc9nFUooyCUomTSsR2e7fnOjKY0I+XyyrLGYKOdzfAePbPR
KCVQv9U3bpCoNt4DBWmFiE8iW68Tl3RsBqcez9ytqwAKphMOM68ZLvENtVtkQHuO
HnMA5M3HB//Vs+OkT+VgDc5yNj5/yXqDq27j7X8p+WGWQWY/NIWaofndeMDdADvM
AKLoVJ3cuU9Hghi76qE=`

	// a generated GUID, for tests
	transactionID := "ac84c56f-80cb-4a88-b970-622156f4920a" // commonName "commonName16092024"
	// transactionID := "c5bc193b-6974-4908-8158-54b48a4b8759" // commonName "commonName13092024_2"
	// transactionID := "b6ed1fd5-8871-4d6d-936e-cac1ecefcc2b" // commonName "commonName13092024"

	eInput := &kms.CSRImportInput{
		CSR: csrPEM,
		Context: kms.Context{
			AppID:         vaultClient.Config.Credentials.AppID,
			TransactionID: transactionID,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Millisecond*10000))
	defer cancel()

	// Start timer
	defer timeTrack(time.Now())

	fmt.Println("CSR Import request")
	eOutput, err := vaultClient.CSRImportWithContext(ctx, eInput)
	if err != nil {
		fmt.Println("CSR Import request failed:", err.Error())
		// os.Exit(1)
	} else {
		fmt.Println("CSR Import request - Success value:" + strconv.FormatBool(eOutput.Success))
	}

	// Get Status
	// The CommonName and TransactionID should match (same as the pair used for the /ImportCertificateCSR call)
	fmt.Println("CSR Status request")
	eInputStatus := &kms.CSRStatusInput{
		CommonName:    "commonName16092024", // "commonName13092024", // "commonName13092024_2", "scepclient",
		TransactionID: transactionID,
	}

	//eOutputStatus, err := vaultClient.CSRStatusWithContext(ctx, eInputStatus)
	eOutputStatus, err := vaultClient.CSRStatus(eInputStatus)
	if err != nil {
		fmt.Println("CSR Status request failed:", err.Error())
		// os.Exit(1)
	} else {
		fmt.Println("CSR Status request - Success:" + strconv.FormatBool(eOutputStatus.Success))
		fmt.Println("CSR Status request - Status:" + eOutputStatus.Result.Status)
		fmt.Println("CSR Status request - Certificate:" + eOutputStatus.Result.Certificate)
	}
}

// Testing the get scep signature CA from cockpit
func testGetSignatureCA(vaultClient *kms.KMS) {

	eInput := &kms.GetSignatureCAInput{
		ScepExternalId: appID,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Millisecond*10000))
	defer cancel()

	fmt.Println("Get Signature CA request")
	eOutput, err := vaultClient.GetSignatureCAWithContext(ctx, eInput)
	if err != nil {
		fmt.Println("Get Signature CA request failed:", err.Error())
		// os.Exit(1)
	} else {
		fmt.Println("Get Signature CA request - Success value:" + strconv.FormatBool(eOutput.Success))
	}

	fmt.Println("Get Signature CA request - Success:" + strconv.FormatBool(eOutput.Success))
	fmt.Println("Get Signature CA request - result:" + eOutput.Result)
}

func testKeysOperations(vaultClient *kms.KMS) {
	resp, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		fmt.Println("Error:", err.Error())
		os.Exit(1)
	}
	defer resp.Body.Close()

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error:", err.Error())
		os.Exit(1)
	}

	// Those are examples of RSA-OAEP-256, AES-GCM and AES-CBC calls
	// Of course the algorithm must be defined according to the key (keyId from the input parameters)
	//		and it depends on the Cockpit Vault (vaultID from the input parameters))
	//		At the time of writing this example, March 2025, only the MPC (Sepior) Cockpit vault does handle AES-CBC
	// ** RSA-OAEP-256 **
	// algorithm := "RSA-OAEP-256"
	// iv := ""
	// aad := ""
	// payload := "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ="
	//
	// ** AES-GCM **
	// 		iv for AES-GCM should be 12 bytes (recommandation for optimal security and performance)
	algorithm := "AES-GCM"
	iv := "YWJjZGVmZ2hpamts"
	aad := "bGFiZWw="
	payload := "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ="
	//
	// ** AES-CBC **
	// 		payload size must be a multiple of 16 (padding done by the client)
	// 		iv for AES-CBC 16 bytes
	// algorithm := "AES-CBC"
	// iv := "ceciestunivdes16" // in b64: "Y2VjaWVzdHVuaXZkZXMxNg=="
	// aad := ""
	// payload := "ceciestuntexta16" // in b64: "Y2VjaWVzdHVudGV4dGExNg=="

	// Encryption
	eInput := &kms.EncryptInput{
		KeyID:     keyID,
		VaultID:   vaultID,
		ID:        0,
		Algorithm: algorithm,
		// Depending on the algorithm, Iv and Aad can be emtpy strings
		Iv:  []byte(iv),
		Aad: []byte(aad),
		// The context can be set here, or here under as in this example
		// Context: map[string]string{
		// 	"appid":  appID,
		// 	"ipaddr": string(ip),
		// 	"http://schemas.microsoft.com/identity/claims/tenantid":     strconv.Itoa(int(tenantID)),
		// 	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": upn,
		// },
		Payload: []byte(payload),
	}

	eInput.Context = make(map[string]string)
	eInput.Context["ipaddr"] = string(ip)
	eInput.Context["appid"] = appID // appid Added As It Is Mandatory
	eInput.Context["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"] = upn

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Millisecond*50000)) // Fab tmp: increase from 10000 to 50000 to have time debuging
	defer cancel()

	// Start timer
	defer timeTrack(time.Now())

	fmt.Println("Encryption request")
	eOutput, err := vaultClient.EncryptWithContext(ctx, eInput)
	if err != nil {
		fmt.Println("Encryption request failed:", err.Error())
		os.Exit(1)
	}

	fmt.Println("Encrypted payload: " + string(eOutput.Result.EncryptedPayload))

	// Decryption
	dInput := &kms.DecryptInput{
		KeyID:     keyID,
		VaultID:   vaultID,
		ID:        0,
		Algorithm: algorithm,
		Payload:   eOutput.Result.EncryptedPayload,
		// Depending on the algorithm, Iv and Aad can be emtpy strings
		//		Note: eOutput.Result.Iv is empty after AES-GCM operation, use the one given for the Encrypt
		Iv:  []byte(iv),
		Aad: []byte(aad),
		Tag: eOutput.Result.Tag, // Tag is needed for AES-GCM
	}

	// Context Information Added As It Is Mandatory
	dInput.Context = make(map[string]string)
	dInput.Context["appid"] = appID

	fmt.Println("Decryption request")
	//dOutput, err := vaultClient.Decrypt(dInput)
	dOutput, err := vaultClient.DecryptWithContext(ctx, dInput)
	if err != nil {
		fmt.Println("Decryption request failed:", err.Error())
		os.Exit(1)
	}

	fmt.Println("Decryption request - Success:", dOutput.Success)
	fmt.Println("Decrypted payload: " + string(dOutput.Result.Payload))

	if string(dOutput.Result.Payload) != payload {
		fmt.Println("ERROR: decrypted payload differs from original payload: " + payload)
	} else {
		fmt.Println("SUCCESS: decrypted payload and original payload are identical")
	}

	// Get Key Id
	getKeyInput := &kms.GetKeyIdInput{
		ExternalID: keyID,
	}

	keyOutput, err := vaultClient.GetKeyIdWithContext(ctx, getKeyInput)
	fmt.Println("ip :: ", string(ip))
	fmt.Println("keyOutput.Result.Key.Name :: ", keyOutput.Result.Key.Name)
	if err != nil {
		fmt.Println("GetKeyId request failed:", err.Error())
		os.Exit(1)
	}
}
