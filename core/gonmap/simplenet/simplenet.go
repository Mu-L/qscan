package simplenet

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

func tcpSend(protocol string, netloc string, data string, duration time.Duration, size int) (string, error) {
	protocol = strings.ToLower(protocol)
	conn, err := net.DialTimeout(protocol, netloc, duration)
	if err != nil {
		return "", fmt.Errorf("STEP1:CONNECT: %w", err)
	}
	defer conn.Close()
	_, err = conn.Write([]byte(data))
	if err != nil {
		return "", fmt.Errorf("STEP2:WRITE: %w", err)
	}
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for buf.Len() < size {
		_ = conn.SetReadDeadline(time.Now().Add(duration))
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", fmt.Errorf("STEP3:READ: %w", err)
		}
		if n < len(tmp) {
			break
		}
	}
	if buf.Len() == 0 {
		return "", fmt.Errorf("STEP3:response is empty")
	}
	return buf.String(), nil
}

func tlsSend(protocol string, netloc string, data string, duration time.Duration, size int) (string, error) {
	protocol = strings.ToLower(protocol)
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}
	dialer := &net.Dialer{
		Timeout:  duration,
		Deadline: time.Now().Add(duration * 2),
	}
	conn, err := tls.DialWithDialer(dialer, protocol, netloc, config)
	if err != nil {
		return "", fmt.Errorf("STEP1:CONNECT: %w", err)
	}
	defer conn.Close()
	_, err = io.WriteString(conn, data)
	if err != nil {
		return "", fmt.Errorf("STEP2:WRITE: %w", err)
	}
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for buf.Len() < size {
		_ = conn.SetReadDeadline(time.Now().Add(duration))
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", fmt.Errorf("STEP3:READ: %w", err)
		}
		if n < len(tmp) {
			break
		}
	}
	if buf.Len() == 0 {
		return "", fmt.Errorf("STEP3:response is empty")
	}
	return buf.String(), nil
}

func Send(protocol string, tls bool, netloc string, data string, duration time.Duration, size int) (string, error) {
	if tls {
		return tlsSend(protocol, netloc, data, duration, size)
	} else {
		return tcpSend(protocol, netloc, data, duration, size)
	}
}
