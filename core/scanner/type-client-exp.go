package scanner

import "net"

type foo4 struct {
	addr net.IP
	port int
}

type EXPClient struct {
	*client
	Handler func(addr net.IP, port int)
}

func NewEXPScanner(config *Config) *EXPClient {
	var client = &EXPClient{
		client:  newConfig(config, config.Threads),
		Handler: func(addr net.IP, port int) {},
	}
	client.pool.Interval = config.Interval
	client.pool.Function = func(in interface{}) {
		value := in.(foo4)
		client.Handler(value.addr, value.port)
	}
	return client
}

func (c *EXPClient) Push(addr net.IP, port int) {
	c.pool.Push(foo4{addr, port})
}
