package main

import (
	"context"
	"fmt"
	"io/ioutil"
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
	baseURL      string
	encryptRoute string
	decryptRoute string

	// Vault and key
	vaultID string
	keyID   string
)

func timeTrack(start time.Time) {
	fmt.Printf("Encryption and decryption took %s\n", time.Since(start))
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

}

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
		BaseURL:      baseURL,
		EncryptRoute: encryptRoute,
		DecryptRoute: decryptRoute,
	}

	vaultClient, err := kms.NewClient(credentials, endpoints)
	if err != nil {
		fmt.Println("Error:", err.Error())
		os.Exit(1)
	}

	resp, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		fmt.Println("Error:", err.Error())
		os.Exit(1)
	}
	defer resp.Body.Close()

	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error:", err.Error())
		os.Exit(1)
	}
	fmt.Println(string(ip))

	// Start timer
	defer timeTrack(time.Now())

	// Encryption
	eInput := &kms.EncryptInput{
		KeyID:     keyID,
		VaultID:   vaultID,
		ID:        0,
		Algorithm: "3",
		// Context: map[string]string{
		// 	"appid":  appID,
		// 	"ipaddr": string(ip),
		// 	"http://schemas.microsoft.com/identity/claims/tenantid":     strconv.Itoa(int(tenantID)),
		// 	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": upn,
		// },
		Payload: []byte("Lorem ipsum dolor sit amet"),
	}

	eInput.Context = make(map[string]string)
	eInput.Context["ipaddr"] = string(ip)
	eInput.Context["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"] = upn

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Millisecond*10000))
	defer cancel()

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
		Algorithm: "3",
		Payload:   eOutput.Result.Payload,
	}

	dOutput, err := vaultClient.Decrypt(dInput)
	if err != nil {
		fmt.Println("Decryption request failed:", err.Error())
		os.Exit(1)
	}

	fmt.Println("Success:", dOutput.Success)
	fmt.Println(string(dOutput.Result.Payload))
}
