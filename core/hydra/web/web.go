package web

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

var (
	LoginFailedError  = errors.New("login failed")
	LoginTimeoutError = errors.New("login timeout")
)

func Check(Host, Username, Domain, Password string, Port int) error {
	var url string
	if Port == 80 {
		url = fmt.Sprintf("http://%s/", Host)
	} else if Port == 443 {
		url = fmt.Sprintf("https://%s/", Host)
	} else {
		url = fmt.Sprintf("http://%s:%d/", Host, Port)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	req.SetBasicAuth(Username, Password)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return LoginFailedError
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return nil
	}
	return LoginFailedError
}
