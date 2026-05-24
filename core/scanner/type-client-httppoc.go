package scanner

import "net/url"

type foo5 struct {
	URL *url.URL
}

type HTTPPOCClient struct {
	*client
	Handler func(URL *url.URL)
}

func NewHTTPPOCScanner(config *Config) *HTTPPOCClient {
	var client = &HTTPPOCClient{
		client:  newConfig(config, config.Threads),
		Handler: func(URL *url.URL) {},
	}
	client.pool.Interval = config.Interval
	client.pool.Function = func(in interface{}) {
		value := in.(foo5)
		client.Handler(value.URL)
	}
	return client
}

func (c *HTTPPOCClient) Push(URL *url.URL) {
	c.pool.Push(foo5{URL})
}
