package request

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"

	"github.com/duokey/duokey-sdk-go/duokey"
	"github.com/pkg/errors"
)

// Request ...
type Request struct {
	HTTPClient   *http.Client
	HTTPRequest  *http.Request
	HTTPResponse *http.Response
	Error        error
	Parameters   interface{}
	Data         interface{}
}

// Operation (GET, POST)
type Operation struct {
	Name       string
	HTTPMethod string
	HTTPPath   string
}

// https://golang.org/pkg/net/http/#NewRequest
// func NewRequestWithContext(ctx context.Context, method, url string, body io.Reader) (*Request, error)

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

	rawurl := path.Join(config.Endpoint, operation.HTTPPath)

	var err error
	httpReq.URL, err = url.Parse(rawurl)
	if err != nil {
		httpReq.URL = &url.URL{}
		err = fmt.Errorf("InvalidEndpointURL (%s)", rawurl)
	}

	r := &Request{
		HTTPClient:  config.HTTPClient,
		HTTPRequest: httpReq,
		Error:       err,
		Parameters:  params,
		Data:        data,
	}

	return r
}

// Send ...
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
		return errors.Wrap(err, "failed make HTTP request")
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

	if err = json.NewDecoder(bytes.NewReader(payload)).Decode(response); err != nil {
		return errors.Wrap(err, "failed to decode response body")
	}

	return nil
}
