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

	// CSR
	csrImportRoute string
	csrStatusRoute string

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
	}

	vaultClient, err := kms.NewClient(credentials, endpoints)
	if err != nil {
		fmt.Println("Error:", err.Error())
		os.Exit(1)
	}

	// testKeysOperations(vaultClient)

	testCSROperations(vaultClient)
}

// Testing the very first implementation of the Cockpit's CSR Import+status operations
func testCSROperations(vaultClient *kms.KMS) {
	var csrPEM string
	csrPEM = `-----BEGIN CERTIFICATE REQUEST-----
MIICojCCAYoCAQAwRjELMAkGA1UEBhMCVVMxFDASBgNVBAoTC3NjZXAtY2xpZW50
MQwwCgYDVQQLEwNNRE0xEzARBgNVBAMTCnNjZXBjbGllbnQwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDTW1LFP6jNNmJqmSfAMZnFBhOtNSGyc4okL4vd
gdFIkKvJgcWFlhQN87zKq+h6PV3qxde4CFz76Plb8lZig/V8YcJTB7FnDkNbaZ7m
E0EIPajlDYfP1jXYA9iK8Lmy3zmtGw9BYo94XQMtJwuz2Qdi2jv+96i2BYOpa3HT
UxHYs0xI/o/AmMZPt5OnLjjlR2Swvne9VuusQYaGocSl3+1jbm4DWAPojBeJSVSe
lMRgfxjQMrr3RLfZB8VQ21ZB+ZjJOkHptZly24i0NsR39RBOnoVdYoyC85/OHGUc
lKM/x+l4QvjUhu+579bb+Ke0UVO0JZBk758D7D7c4humvIojAgMBAAGgFzAVBgkq
hkiG9w0BCQcxCBMGc2VjcmV0MA0GCSqGSIb3DQEBCwUAA4IBAQAoZYQS8l5CsOsY
gVyTtx9T6wREeK4000MQ2CSopzivHwGONY97cOyulbmXkamFofybwahwe9jipQM4
K/1W1y38wkn0yfJnXfej9xoDP0u9PWuNn4StMvmRR1tuUFYsjuKk1XVuO8xn3YQu
1QgcX0QiSD+hg4gX1LXNd1UdapnpAHRwUh5MTvHdZIS/SArNd9sPRejc8kL7X6bo
UnT2RRZ+f4PeetNVLcPW2nz/PiuZenxk/2erUFnTeGTXLPO0/TBQUZlduEB7bGPA
l7clZSSpZfmnkzR9mpTLPzcGfoUuA5OcQ3OY8iSlF7/52NS/bNocuaUIoHiMVFfp
HoDXb1Y5
-----END CERTIFICATE REQUEST-----`

	eInput := &kms.CSRImportInput{
		CSR: csrPEM,
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

	fmt.Println("Output:", eOutput)

	// Get Status
	fmt.Println("CSR Status request")
	eInputStatus := &kms.CSRStatusInput{
		CommonName: "scepclient",
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

	// define the algorithm, according to the key
	algorithm := "RSA-OAEP-256"
	// algorithm := "AES-GCM"

	// Encryption
	eInput := &kms.EncryptInput{
		KeyID:     keyID,
		VaultID:   vaultID,
		ID:        0,
		Algorithm: algorithm,
		// The context can be set here, or here under as in this example
		// Context: map[string]string{
		// 	"appid":  appID,
		// 	"ipaddr": string(ip),
		// 	"http://schemas.microsoft.com/identity/claims/tenantid":     strconv.Itoa(int(tenantID)),
		// 	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": upn,
		// },
		Payload: []byte("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ="),
	}

	eInput.Context = make(map[string]string)
	eInput.Context["ipaddr"] = string(ip)
	eInput.Context["appid"] = appID // appid Added As It Is Mandatory
	eInput.Context["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"] = upn

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Millisecond*10000))
	defer cancel()

	// Start timer
	defer timeTrack(time.Now())

	fmt.Println("Encryption request")
	eOutput, err := vaultClient.EncryptWithContext(ctx, eInput)
	if err != nil {
		fmt.Println("Encryption request failed:", err.Error())
		os.Exit(1)
	}

	// Decryption
	dInput := &kms.DecryptInput{
		KeyID:     keyID,
		VaultID:   vaultID,
		ID:        0,
		Algorithm: algorithm,
		Payload:   eOutput.Result.EncryptedPayload,
		// Iv needed only for AES-GCM decryption - will be an empty string for RSA operations and unused, but can be commented out
		Iv: eOutput.Result.Iv,
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

	fmt.Println("Success:", dOutput.Success)
	fmt.Println("Decrypted payload: " + string(dOutput.Result.Payload))

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
