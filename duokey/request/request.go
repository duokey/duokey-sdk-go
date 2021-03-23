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
)

const (
	HeaderTenantID = "Abp.TenantId"
)

// Request stores the data needed to make a call to the DuoKey API and store the response
// as well as a possible error
type Request struct {
	HTTPClient   *http.Client
	HTTPRequest  *http.Request
	HTTPResponse *http.Response
	Error        error
	Parameters   interface{} // Parameters needed to build the request body
	Response     interface{} // Stores the deserialized response
}

// Operation (GET, POST, etc.). The URL of the endpoint is given by baseURL + Route.
type Operation struct {
	Name       string
	HTTPMethod string
	BaseURL    string
	Route      string
}

// New returns a pointer to a request.
// params contains the input parameters needed to build the request body.
// response is pointer value to an object which the request's response
// payload will be deserialized to.
func New(config duokey.Config, operation *Operation, params interface{}, response interface{}) *Request {

	var err error
	var method string

	switch operation.HTTPMethod {
	case http.MethodDelete,
		http.MethodGet,
		http.MethodPost,
		http.MethodPut:
		method = operation.HTTPMethod
	default:
		err = fmt.Errorf("Unknown HTTP method: %s", operation.HTTPMethod)
	}

	httpReq, _ := http.NewRequest(method, "", nil)

	rawurl := operation.BaseURL + operation.Route

	httpReq.URL, err = url.Parse(rawurl)
	if err != nil {
		httpReq.URL = &url.URL{}
		err = fmt.Errorf("Invalid endpoint URL (%s)", rawurl)
	}

	// Each request must include the tenant ID
	httpReq.Header.Add(HeaderTenantID, fmt.Sprint(config.Credentials.TenantID))

	httpReq.Header.Add("Content-Type", "application/json")

	r := &Request{
		HTTPClient:  config.HTTPClient,
		HTTPRequest: httpReq,
		Error:       err,
		Parameters:  params,
		Response:    response,
	}

	return r
}

// Send transmits the request to a DuoKey server and returns an error if an
// unexpected issue is encountered. The deserialized response can be found in
// r.Data.
func (r *Request) Send() error {

	if r.Error != nil {
		return errors.Wrap(r.Error, "bad request")
	}

	body := &bytes.Buffer{}
	if r.Parameters != nil {
		if err := json.NewEncoder(body).Encode(r.Parameters); err != nil {
			return errors.Wrap(err, "failed to serialize request body")
		}
	}

	r.HTTPRequest.Body = ioutil.NopCloser(body)

	var err error

	if r.HTTPResponse, err = r.HTTPClient.Do(r.HTTPRequest); err != nil {
		r.Error = err
		return errors.Wrap(err, "failed to make HTTP request")
	}

	if err = parseHTTPResponse(r.HTTPResponse, r.Response); err != nil {
		r.Error = err
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
	r.HTTPRequest = r.HTTPRequest.WithContext(ctx)
}
