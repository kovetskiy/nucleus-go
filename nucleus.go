package nucleus

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kovetskiy/go-srv"
	"github.com/kovetskiy/lorg"
	"github.com/seletskiy/hierr"
)

var (
	logger      = lorg.NewDiscarder()
	funcRequest = request
)

// SetLogger for all package operations, you can be calm, nucleus-go doesn't
// write anything unless you set logger.
func SetLogger(log lorg.Logger) { logger = log }

// User represents information about authentificated user.
type User struct {
	// Name of given user.
	Name string `json:"username"`
	// Info from remote OAuth service.
	Info map[string]interface{} `json:"userinfo"`
	// CreateDate of given user.
	CreateDate int64 `json:"create_date"`
}

var (
	address      = "_nucleus"
	timeout      = time.Duration(0)
	certificates = x509.NewCertPool()
	retries      = 1
	useragent    = "nucleus-go"
)

var (
	// ErrInvalidToken describes that specified token is has been revoked or
	// just contains of information that doesn't seem like a nucleus token.
	ErrInvalidToken = errors.New("token is invalid")
)

// ErrorMultiple is a set of errors that occurred during operations with
// nucleus nodes.
type ErrorMultiple []error

// Error returns string representation of multiple errors
func (err ErrorMultiple) Error() string {
	if len(err) == 1 {
		return err[0].Error()
	}

	top := errors.New("nucleus: multiple errors")
	for _, nested := range err {
		top = hierr.Push(top, nested)
	}
	return top.Error()
}

// AddCertificate decodes specified pem block,  parses certificate and add it
// to certificates pool
func AddCertificate(pemData []byte) error {
	pemBlock, _ := pem.Decode(pemData)
	if pemBlock == nil {
		return fmt.Errorf(
			"invalid certificate: PEM data is not found",
		)
	}

	certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return fmt.Errorf("invalid certificate: %s", err)
	}

	certificates.AddCert(certificate)

	return nil
}

// AddCertificateFile reads specified filepath and adds certificate to pool
func AddCertificateFile(path string) error {
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	return AddCertificate(pemData)
}

// SetAddress of nucleus server that will be used for authentification
// Default: _nucleus
func SetAddress(nucleus string) {
	address = nucleus
}

// SetTimeout for http operation including connection, any redirects,  reading
// of response body.
// Default: 0
func SetTimeout(time time.Duration) {
	timeout = time
}

// SetRetries of operations with one nucleus server.
// Default: 1
func SetRetries(count int) {
	retries = count
}

// SetUserAgent that should be used for http requests
// Default: nucleus-go
func SetUserAgent(agent string) {
	useragent = agent
}

// Authentificate user using specified authentification token.
func Authentificate(token string) (*User, error) {
	addresses, err := getAddresses(address)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certificates,
			},
		},
		Timeout: timeout,
	}

	errors := ErrorMultiple{}
	for retry := 1; retry <= retries; retry++ {
		for _, address := range addresses {
			user, err, more := funcRequest(client, address, token)
			if err != nil {
				errors = append(errors, err)
				logger.Error(err)
				if more {
					continue
				}

				return nil, errors
			}

			return user, nil
		}
	}

	return nil, errors
}

func getAddresses(address string) ([]string, error) {
	if strings.HasPrefix(address, "_") {
		logger.Debugf("resolving SRV record %s", address)

		addresses, err := srv.Resolve(address)
		if err != nil {
			return nil, err
		}

		logger.Debugf(
			"SRV record %s has been resolved to %q",
			address, addresses,
		)
		return addresses, nil
	}

	return []string{address}, nil
}

func request(
	client *http.Client,
	address string,
	token string,
) (*User, error, bool) {
	var host string
	if strings.Contains(address, "://") {
		uri, err := url.Parse(address)
		if err != nil {
			return nil, hierr.Errorf(
				err,
				"can't parse URL '%s'", address,
			), true
		}

		host = uri.Host
	} else {
		host = address
	}

	request, err := getRequest(host, token)
	if err != nil {
		return nil, err, true
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, hierr.Errorf(
			err, "%s: can't exec http request", host,
		), true
	}

	if response.StatusCode == http.StatusUnauthorized {
		return nil, ErrInvalidToken, false
	}

	if response.StatusCode != http.StatusOK {
		return nil, hierr.Errorf(
			err,
			"%s: unexpected server status %d %s",
			host, response.StatusCode, response.Status,
		), true
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, hierr.Errorf(
			err,
			"%s: can't read server response",
			host,
		), true
	}

	defer response.Body.Close()

	var user User
	err = json.Unmarshal(body, &user)
	if err != nil {
		return nil, hierr.Errorf(
			hierr.Push(err, string(body)),
			"%s: can't unmarshal server response",
			host,
		), true
	}

	return &user, nil, false
}

func getRequest(host, token string) (*http.Request, error) {
	request, err := http.NewRequest(
		"GET", "https://"+host+"/api/v1/user", nil,
	)
	if err != nil {
		return nil, hierr.Errorf(
			err,
			"can't create new request to '%s'",
			host,
		)
	}

	request.SetBasicAuth("", token)
	request.Header.Set("User-Agent", useragent)

	return request, nil
}
