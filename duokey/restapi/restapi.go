package restapi

// Config allows the user to customize the routes of the API
type Config struct {
	BasePath   string
	KMSEncrypt string
	KMSDecrypt string
}
