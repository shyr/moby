package libnetwork

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/Sirupsen/logrus"
	gorb "github.com/kobolog/gorb/core"
)

type GorbClient struct {
	url string
}

func NewGorbClient(url string) *GorbClient {
	return &GorbClient{url: url}
}

func MakeGorbServiceOptions(host string, port uint16, protocol string) gorb.ServiceOptions {
	return gorb.ServiceOptions{
		Host:       host,
		Port:       port,
		Protocol:   protocol,
		Method:     "rr",
		Persistent: true,
	}
}

func MakeGorbBackendOptions(host string, port uint16) gorb.BackendOptions {
	return gorb.BackendOptions{
		Host:   host,
		Port:   port,
		Method: "tunnel",
	}
}

func (c *GorbClient) PutService(service string, options gorb.ServiceOptions) (*http.Response, error) {
	if err := options.Validate(nil); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/service/%s", service)
	return c.sendRequest(http.MethodPut, path, options)
}

func (c *GorbClient) DeleteService(service string) (*http.Response, error) {
	path := fmt.Sprintf("/service/%s", service)
	return c.sendRequest(http.MethodDelete, path, nil)
}

func (c *GorbClient) PutBackend(service string, backend string, options gorb.BackendOptions) (*http.Response, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/service/%s/%s", service, backend)
	return c.sendRequest(http.MethodPut, path, options)
}

func (c *GorbClient) DeleteBackend(service string, backend string) (*http.Response, error) {
	path := fmt.Sprintf("/service/%s/%s", service, backend)
	return c.sendRequest(http.MethodDelete, path, nil)
}

func (c *GorbClient) createRequest(method string, path string, body interface{}) (*http.Request, error) {
	u, err := url.Parse(c.url)
	if err != nil {
		return nil, err
	}

	u.Path = path

	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequest(method, u.String(), bytes.NewBuffer(b))
		if err != nil {
			return nil, err
		}

		req.Header.Add("Accept", "application/json")

		return req, nil
	} else {
		return http.NewRequest(method, u.String(), nil)
	}
}

func (c *GorbClient) sendRequest(method string, path string, body interface{}) (*http.Response, error) {
	logrus.Debugf("Sending gorb request: path: %s body: %+v", path, body)

	req, err := c.createRequest(method, path, body)
	if err != nil {
		return nil, err
	}

	client := http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s: %s", resp.Status, respBody)
	}

	logrus.Debugf("Gorb request sent: path: %s body: %+v", path, body)

	return resp, nil
}
