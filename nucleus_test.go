package nucleus

import (
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/reconquest/srv-go"
	"github.com/kovetskiy/lorg"
	"github.com/stretchr/testify/assert"
)

func init() {
	logger = lorg.NewLog()
	logger.(*lorg.Log).SetLevel(lorg.LevelDebug)
}

func TestGetRequest_UseSpecifiedHostnameAndToken(t *testing.T) {
	defer reset()
	test := assert.New(t)

	request, err := getRequest("foo", "bar")
	test.NoError(err)
	test.Equal("https://foo/api/v1/user", request.URL.String())
	test.Equal("GET", request.Method)
	test.Equal("Basic OmJhcg==", request.Header.Get("Authorization"))
	test.Equal("nucleus-go", request.Header.Get("User-Agent"))
}

func TestGetRequest_UseSpecifiedUserAgent(t *testing.T) {
	defer reset()
	test := assert.New(t)

	SetUserAgent("xxx")
	request, _ := getRequest("foo", "bar")
	test.Equal("xxx", request.Header.Get("User-Agent"))
}

func TestGetAddresses_ResolveSRV(t *testing.T) {
	defer reset()
	test := assert.New(t)

	srv.Testing_RecordToResult = map[string][]string{
		"_x": []string{"a", "b", "c"},
	}

	addresses, err := getAddresses("_x")
	test.NoError(err)
	test.EqualValues([]string{"a", "b", "c"}, addresses)
}

func TestGetAddresses_ErrorIfCantResolve(t *testing.T) {
	defer reset()
	test := assert.New(t)

	_, err := getAddresses("_y")
	test.Error(err)
}

func TestGetAddresses_OneIfNotSRV(t *testing.T) {
	defer reset()
	test := assert.New(t)

	addresses, err := getAddresses("x")
	test.NoError(err)
	test.EqualValues([]string{"x"}, addresses)
}

func TestSetAddress(t *testing.T) {
	defer reset()
	test := assert.New(t)

	SetAddress("blah")
	test.Equal("blah", address)
}

func TestSetTimeout(t *testing.T) {
	defer reset()
	test := assert.New(t)

	SetTimeout(time.Minute)
	test.Equal(time.Minute, timeout)
}

func TestSetRetries(t *testing.T) {
	defer reset()
	test := assert.New(t)

	SetRetries(50)
	test.Equal(50, retries)
}

func TestAddCertificate_AddsToCertificatesPool(t *testing.T) {
	defer reset()
	test := assert.New(t)

	err := AddCertificate([]byte(`-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAIpyMnhsVvD3MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTYwNzI1MjAwNDU0WhcNNDMxMjEwMjAwNDU0WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA3cQZAHsaixI9R06DseM4Qc/H4ldIpiYyu8+mNzU3h136fxdhw6nDFIcy
4Gcc8gf/tSxcILWIXRJOiqvlXKOEkevNe7x2xgQoPyXFWkeCOaVf1dj9u7XDoFZP
Nw0q6rN5FliUcc37yvubWFvr+z7hD3OFhwpiRUDwXF9TG8Z6PxZxmoyuj1DXE6V1
QxoICtTAq3FIh3Nd8laQKP+IELQaF5NDFe3dV8aDGLoSU5gJkZvRs6tAKW1doqZJ
yTxYj8tvcf99xONUzDtGB9W3KKspUq16cyU6n3LuqkUITkRYngC4CxlIzXzXMMgS
US9F4vhBmrtI92XHFZQjhndCOLRBEQIDAQABo1AwTjAdBgNVHQ4EFgQU+Z0D+e4Z
hoJSBbbS12BUBn6VD0owHwYDVR0jBBgwFoAU+Z0D+e4ZhoJSBbbS12BUBn6VD0ow
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAyR75vWrJUWgz5zKGsAwv
iQA1NySPghhNu4WLSqwQ3R3QBuyT8YPOM+QGvlUGZAqDrl11Q8qhuVgXUtum3Ezh
aWI4zge4KqzY4xAGUdeMw84rRVAgc6R1i9hbYnI7akI4HhHa2tBJMXELwsRwnhJK
tWPlNORmekjzSv/HbsuZT3l86ARBwuzfnWYKKPhD/SoyQgzuFILzT11XQzC0CzSO
zHEeMmAYpPicwaMnEvAJrRpQTuk6CfCVBGeW1O7nRulab3zWWSSzmyst77HKllUG
aUHULe24P+v8VusC+oclINauaKm2b2k4ZyOuDcipw50MU59kyujn0KWNTgEBnhe2
ng==
-----END CERTIFICATE-----`))
	test.NoError(err)
	test.Len(certificates.Subjects(), 1)
}

func TestAddCertificateFile_AddsToCertificatesPool(t *testing.T) {
	defer reset()
	test := assert.New(t)

	file, err := ioutil.TempFile(os.TempDir(), "")
	test.NoError(err)

	file.WriteString(`-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAIpyMnhsVvD3MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTYwNzI1MjAwNDU0WhcNNDMxMjEwMjAwNDU0WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA3cQZAHsaixI9R06DseM4Qc/H4ldIpiYyu8+mNzU3h136fxdhw6nDFIcy
4Gcc8gf/tSxcILWIXRJOiqvlXKOEkevNe7x2xgQoPyXFWkeCOaVf1dj9u7XDoFZP
Nw0q6rN5FliUcc37yvubWFvr+z7hD3OFhwpiRUDwXF9TG8Z6PxZxmoyuj1DXE6V1
QxoICtTAq3FIh3Nd8laQKP+IELQaF5NDFe3dV8aDGLoSU5gJkZvRs6tAKW1doqZJ
yTxYj8tvcf99xONUzDtGB9W3KKspUq16cyU6n3LuqkUITkRYngC4CxlIzXzXMMgS
US9F4vhBmrtI92XHFZQjhndCOLRBEQIDAQABo1AwTjAdBgNVHQ4EFgQU+Z0D+e4Z
hoJSBbbS12BUBn6VD0owHwYDVR0jBBgwFoAU+Z0D+e4ZhoJSBbbS12BUBn6VD0ow
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAyR75vWrJUWgz5zKGsAwv
iQA1NySPghhNu4WLSqwQ3R3QBuyT8YPOM+QGvlUGZAqDrl11Q8qhuVgXUtum3Ezh
aWI4zge4KqzY4xAGUdeMw84rRVAgc6R1i9hbYnI7akI4HhHa2tBJMXELwsRwnhJK
tWPlNORmekjzSv/HbsuZT3l86ARBwuzfnWYKKPhD/SoyQgzuFILzT11XQzC0CzSO
zHEeMmAYpPicwaMnEvAJrRpQTuk6CfCVBGeW1O7nRulab3zWWSSzmyst77HKllUG
aUHULe24P+v8VusC+oclINauaKm2b2k4ZyOuDcipw50MU59kyujn0KWNTgEBnhe2
ng==
-----END CERTIFICATE-----`)
	test.NoError(file.Sync())
	test.NoError(file.Close())
	defer os.Remove(file.Name())

	err = AddCertificateFile(file.Name())
	test.NoError(err)
	test.Len(certificates.Subjects(), 1)
}

func TestErrorMultiple_ReturnsAsIsIfOnlyOneError(t *testing.T) {
	defer reset()
	test := assert.New(t)

	err := ErrorMultiple{}
	err = append(err, errors.New("foo"))
	test.Equal(err.Error(), "foo")
}

func TestErrorMultiple_CreatesHierarchicalError(t *testing.T) {
	defer reset()
	test := assert.New(t)

	err := ErrorMultiple{}
	err = append(err, errors.New("foo"), errors.New("bar"))
	test.Equal(
		err.Error(),
		"nucleus: multiple errors\n"+
			"├─ foo\n"+
			"└─ bar",
	)
}

func TestAuthenticate_DoRequestConsideringRetries(t *testing.T) {
	defer reset()
	test := assert.New(t)

	addresses := []string{}
	tokens := []string{}

	funcRequest = func(
		client *http.Client,
		address, token string,
	) (*User, error, bool) {
		test.NotNil(client)
		addresses = append(addresses, address)
		tokens = append(tokens, token)
		return nil, errors.New("foo"), true
	}

	srv.Testing_RecordToResult = map[string][]string{
		"_x": []string{"host1", "host2"},
	}

	SetRetries(3)
	SetAddress("_x")

	user, err := Authenticate("tok")
	test.Nil(user)
	test.EqualError(
		err,
		"nucleus: multiple errors\n"+
			"├─ foo\n"+
			"├─ foo\n"+
			"├─ foo\n"+
			"├─ foo\n"+
			"├─ foo\n"+
			"└─ foo",
	)

	test.EqualValues(
		[]string{"host1", "host2", "host1", "host2", "host1", "host2"},
		addresses,
	)
	test.EqualValues(
		[]string{"tok", "tok", "tok", "tok", "tok", "tok"},
		tokens,
	)
}

func TestAuthenticate_ReturnsUser(t *testing.T) {
	defer reset()
	test := assert.New(t)

	calls := 0
	funcRequest = func(
		client *http.Client,
		address, token string,
	) (*User, error, bool) {
		test.NotNil(client)
		calls++
		return &User{Name: "wowow"}, nil, false
	}

	SetRetries(3)
	SetAddress("host")

	user, err := Authenticate("tok")
	test.EqualValues(&User{Name: "wowow"}, user)
	test.NoError(err)

	test.EqualValues(
		1,
		calls,
	)
}
