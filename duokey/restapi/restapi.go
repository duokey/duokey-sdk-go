package restapi

// Config allows the user to customize the routes of the API
type Config struct {
	BasePath   string
	// KMS service
	KMSEncrypt string
	KMSDecrypt string
}
