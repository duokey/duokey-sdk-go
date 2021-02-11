package request

import (
	_ "io"
	"net/http"

	"github.com/duokey/duokey-sdk-go/duokey"
)

// Request ...
type Request struct {

	HTTPRequest            *http.Request
	HTTPResponse           *http.Response
	Parameters interface{}
	Response interface{}

}

// Operation (GET, POST)
type Operation struct {
	Name       string
	HTTPMethod string
	HTTPPath   string
}


// https://golang.org/pkg/net/http/#NewRequest
// func NewRequestWithContext(ctx context.Context, method, url string, body io.Reader) (*Request, error)


// func (c *Client) NewRequest(operation *request.Operation, params interface{}, data interface{}) *request.Request {
//	return request.New(c.Config, c.ClientInfo, c.Handlers, c.Retryer, operation, params, data)
//}

// New ...
func New(config duokey.Config, operation *Operation, params interface{}, data interface{}) *Request {

	var method string
	switch operation.HTTPMethod {
	case http.MethodGet:
		method = operation.HTTPMethod
	default:
		method = http.MethodPost
	}
	
	httpReq, _ := http.NewRequest(method, "", nil)

	r := &Request{
		HTTPRequest: httpReq,
	}

	return r
}



// Send ...
func (r *Request) Send() error {

	

	return nil
}