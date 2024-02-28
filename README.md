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
### Example

Define the following environment variables:

| Envirnment variable | Description |
|--- |--- |
| DUOKEY_APP_ID | The application ID |
| DUOKEY_UPN | The user principal name |
| DUOKEY_ISSUER | The named external system that provides identity and API access by issuing an OAuth access token |
| DUOKEY_CLIENT_ID | The client id for credentials to query the DuoKey API |
| DUOKEY_CLIENT_SECRET | The client secret for credentials to query the DuoKey API |
| DUOKEY_VAULT_ID | The vault to use for encryption and decryption |
| DUOKEY_KEY_ID | The DuoKey key ID to use for encryption and decryption |
| DUOKEY_HEADER_TENANT_ID | |
| DUOKEY_TENANT_ID | The tenant id for the DuoKey organization |
| DUOKEY_USERNAME | The username |
| DUOKEY_PASSWORD | The password |
| DUOKEY_SCOPE | The scope of the token |
| DUOKEY_BASE_URL | The base URL of the DuoKey API |
| DUOKEY_ENCRYPT_ROUTE | The DuoKey API route to be used to make an encryption request |
| DUOKEY_DECRYPT_ROUTE | The DuoKey API route to be used to make a decryption request |
| DUOKEY_IMPORT_ROUTE | The DuoKey API route to be used to import a key |

Run the example:

```bash
cd examples/kms
go run main.go
```

## License

This project is distributed under the terms of the Mozilla Public License (MPL) 2.0, see [LICENSE](LICENSE) for details.
