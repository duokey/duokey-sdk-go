package restapi

// Config allows the user to customize the routes of the API
type Config struct {
	BasePath string
	// KMS service
	KMSEncryptRoute string
	KMSDecryptRoute string
}
