package request

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/duokey/duokey-sdk-go/duokey"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

// Request ...
type Request struct {
	Token        *oauth2.Token
	HTTPClient   *http.Client
	HTTPRequest  *http.Request
	HTTPResponse *http.Response
	Error        error
	Parameters   interface{}
	Data         interface{}

	context context.Context
}

// Operation (GET, POST)
type Operation struct {
	Name       string
	HTTPMethod string
	HTTPPath   string
}

// New returns a pointer to a request.
// Params contains the input parameters needed to build the request body.
// Data is pointer value to an object which the request's response
// payload will be deserialized to.
func New(config duokey.Config, operation *Operation, params interface{}, data interface{}) *Request {

	var method string
	switch operation.HTTPMethod {
	case http.MethodDelete,
		http.MethodGet,
		http.MethodPost,
		http.MethodPut:
		method = operation.HTTPMethod
	default:
		method = http.MethodPost
	}

	httpReq, _ := http.NewRequest(method, "", nil)

	rawurl := config.Routes.BasePath + operation.HTTPPath

	var err error
	httpReq.URL, err = url.Parse(rawurl)
	if err != nil {
		httpReq.URL = &url.URL{}
		err = fmt.Errorf("InvalidEndpointURL (%s)", rawurl)
	}

	httpReq.Header.Add("Abp.TenantId", fmt.Sprint(config.Credentials.TenantID))
	httpReq.Header.Add("Content-Type", "application/json")

	r := &Request{
		HTTPClient:  config.HTTPClient,
		HTTPRequest: httpReq,
		Error:       err,
		Parameters:  params,
		Data:        data,
	}

	return r
}

// Send transmits the request to a DuoKey server and returns an error if an
// unexpected issue is encountered. The deserialized response can be found in
// r.Data.
func (r *Request) Send() error {

	body := &bytes.Buffer{}
	if r.Parameters != nil {
		if err := json.NewEncoder(body).Encode(r.Parameters); err != nil {
			return errors.Wrap(err, "failed to serialize request body")
		}
	}

	r.HTTPRequest.Body = ioutil.NopCloser(body)

	var err error
	if r.HTTPResponse, err = r.HTTPClient.Do(r.HTTPRequest); err != nil {
		return errors.Wrap(err, "failed to make HTTP request")
	}

	if err = parseHTTPResponse(r.HTTPResponse, r.Data); err != nil {
		return errors.Wrap(err, "failed to parse HTTP response")
	}

	return nil
}

func parseHTTPResponse(resp *http.Response, response interface{}) error {
	defer resp.Body.Close()

	var payload []byte
	var err error

	if resp.StatusCode >= 300 {
		return fmt.Errorf("request failed with status %d", resp.StatusCode)
	}

	if payload, err = ioutil.ReadAll(resp.Body); err != nil {
		return errors.Wrap(err, "failed to read response body")
	}

	if response != nil {
		if err = json.NewDecoder(bytes.NewReader(payload)).Decode(response); err != nil {
			return errors.Wrap(err, "failed to decode response body")
		}
	}

	return nil
}

// SetContext adds a context to a request.
func (r *Request) SetContext(ctx context.Context) {
	if ctx == nil {
		panic("context cannot be nil")
	}
	r.context = ctx
	r.HTTPRequest = r.HTTPRequest.WithContext(ctx)
}
