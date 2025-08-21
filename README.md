# DuoKey SDK for Go

[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/duokey/duokey-sdk-go)](https://goreportcard.com/report/github.com/duokey/duokey-sdk-go)

duokey-sdk-go is the official DuoKey SDK for the Go programming language. Its architecture is
inspired by the [AWS SDK for Go](https://github.com/aws/aws-sdk-go) and the
[Fortanix SDKMS Go SDK](https://github.com/fortanix/sdkms-client-go).

## Getting Started

### Installing

Use `go get` to retrieve the SDK and add it to your Go module dependencies:

```bash
go get github.com/duokey/duokey-sdk-go
```

### Dependencies

The metadata of the SDK dependencies can be found in the Go module file [`go.mod`](go.mod).
### Sample CreateEncryptRequest
```bash
{
  "keyid": "2e974659-64e8-4e8a-b702-c5133620bd0f",
  "vaultid": "1ac93d40-69c2-4f69-6034-08d8d6af37bc",
  "payload": "DFGVzLO1Q9j7a3pPWo4L+Q9Ku670XptGP7pXKpvryMtoRHESgbLaZrc0HVew1loviLxMceMUSKPz85wpKIIos8JfSIgLYDnCCRnMDtf2vS2IXUwrW+/KZJRdsr2OyzAQzxGsOrVmLRQNctj9/VH+cbZWlxbgzlFnLayxS2VQvd3OLKC+J8J2Xx6LvD5Uzry3R14VGHh/8eaXfGzGMox2GzV40BrqCJIDB8t5T4QIHUHqGhhJt70VPUTGwf6XsSg55BFZVCVOvj8g/YhVS2dsvsNeL4rEe1k6myQeGo/VhYIHYYY3WLIAIsY4sNsljfiFyWZHn3nvqnLQpxbJDuCKOw==",
  "algorithm": "3",
   "context": {
    "appid": "87c3ab90-793b-7733-6060-1329a75f6b06",
    "ttp://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "john.doe@example.com"
}
}
```
## Cockpit routes
This SDK covers a few routes of the Cockpit, and will be further enriched according to the needs of the GoLang projects.  

An overview of the covered routes is found here under, with the list of parameters that have a "_ROUTE" suffix.

## Parameters
The parameters are passed as arguments when instanciating a client with `kms.NewClient()` or `NewClientWithLogger()`.

About the timeouts for the http calls to the Cockpit:
- For token operations as checkToken() and the similar AuthenticateUser(), the timeout is passed as an optional last parameter to `kms.NewClient()` or `NewClientWithLogger()`
- For the different operation calls, a context with timeout can be passed, using the function suffixed `WithContext`, as `GetKeyIdWithContext()`, `EncryptWithContext()`, etc.

For the expected parameters, see the section here under.

## Parameters list to run the examples + some explanation

To run the example, define the following environment variables that will be passed as parameter to instanciate the client:

|Environment variable | Description |
|--- |--- |
|DUOKEY_APP_ID | The application ID |
|DUOKEY_UPN | The user principal name |
|DUOKEY_ISSUER | The named external system that provides identity and API access by issuing an OAuth access token |
|DUOKEY_CLIENT_ID | The client id for credentials to query the DuoKey API |
|DUOKEY_CLIENT_SECRET | The client secret for credentials to query the DuoKey API |
|DUOKEY_VAULT_ID | The vault to use for encryption and decryption |
|DUOKEY_KEY_ID | The DuoKey key ID to use for encryption and decryption |
|DUOKEY_HEADER_TENANT_ID | |
|DUOKEY_TENANT_ID | The tenant id for the DuoKey organization |
|DUOKEY_USERNAME | The username |
|DUOKEY_PASSWORD | The password |
|DUOKEY_SCOPE | The scope of the token |
|DUOKEY_BASE_URL | The base URL of the DuoKey API |

Optional environment variables - default values are used if not set:

|Environment variable | Description |
|--- |--- |
|DUOKEY_CREATEKEY_ROUTE | The DuoKey API route to be used to create a new key |
|DUOKEY_DELETEKEY_ROUTE | The DuoKey API route to be used to delete an existing key |
|DUOKEY_ENCRYPT_ROUTE | The DuoKey API route to be used to make an encryption request |
|DUOKEY_DECRYPT_ROUTE | The DuoKey API route to be used to make a decryption request |
|DUOKEY_IMPORT_ROUTE | The DuoKey API route to be used to import a key |
|DUOKEY_GETKEYID_ROUTE | The DuoKey API route to be used to get a key by its external id |
|DUOKEY_GETKEYBYNAME_ROUTE | The DuoKey API route to be used to get a key by its name |
|DUOKEY_CSRIMPORT_ROUTE | The DuoKey API route to be used to import a CSR |
|DUOKEY_CSRSTATUS_ROUTE | The DuoKey API route to be used to import get the CSR Status and get the signed certificate |
|DUOKEY_GETSIGNATURECA_ROUTE | The DuoKey API route to be used to get the CA signature |
|DUOKEY_CREATEOREDITOBJECT_ROUTE | The DuoKey API route to be used to create or edit an object (pkcs11) |
|DUOKEY_GETOBJECTBYNAME_ROUTE | The DuoKey API route to be used to get an object by its name (pkcs11) |
This list also gives the information about which Cockpit routes are currently handled by this sdk version.  
It is to be noted that at the time of writing (summer 2025), the DUOKEY_CSRIMPORT_ROUTE, DUOKEY_CSRSTATUS_ROUTE and DUOKEY_GETSIGNATURECA_ROUTE are functionalities first developped to handle certificates updates according to the SCEP specification, and further adapted to demonstrate the EST implementation. Those functionalities will be further developped in the near future. 

To run an example, the main() of `examples/kms/main.go` should be adapted and the variable correctly set.

Run the example:

```bash
cd examples/kms
go run main.go
```

## License

This project is distributed under the terms of the Mozilla Public License (MPL) 2.0, see [LICENSE](LICENSE) for details.
