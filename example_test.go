package nucleus_test

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/kovetskiy/nucleus-go"
)

var certificate = []byte(`-----BEGIN CERTIFICATE-----
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

var key = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDdxBkAexqLEj1H
ToOx4zhBz8fiV0imJjK7z6Y3NTeHXfp/F2HDqcMUhzLgZxzyB/+1LFwgtYhdEk6K
q+Vco4SR6817vHbGBCg/JcVaR4I5pV/V2P27tcOgVk83DSrqs3kWWJRxzfvK+5tY
W+v7PuEPc4WHCmJFQPBcX1Mbxno/FnGajK6PUNcTpXVDGggK1MCrcUiHc13yVpAo
/4gQtBoXk0MV7d1XxoMYuhJTmAmRm9Gzq0ApbV2ipknJPFiPy29x/33E41TMO0YH
1bcoqylSrXpzJTqfcu6qRQhORFieALgLGUjNfNcwyBJRL0Xi+EGau0j3ZccVlCOG
d0I4tEERAgMBAAECggEAZzlEzfV/GGaoAU3pfN6fq/p0NsWb+kJjcQopex8ZNrgm
xgtzJSkata5snwk/7uSMQJ9iTpNQ4smHp4J1o1Y1edqBbev+eRMsTKBfKTOJyR1R
628yQ7JKWZJzEtPdOxvI6/7VMdfIMOZGm61FvU+6YH/MElxh+4xLlSOFwrLy6fPB
FzlPG/DmNwUrU4L4rGyevwjq9Odn5KIQwUdtDp4rq0OVamMGRSwbju16PQ+zQgEq
1nMRv6+iP3G3w7B2mo7cmu204A8xiOHsD1/WV+AdxyOWKOHmzX4jH42bEvaZBSGO
dYjnBNZM3zVANWQ2ugySzYdwQ1eMdvCov4AVZPdJ1QKBgQD/lJhlTTD+J4gLqmCp
0HEvKIjOj4tslTgF/rKHcKEffr/7G/g9zJEqhvjZhPbdFrwE7t8wRb6SRRGe8azV
Q04UGJ3HsStcDu0ewYc+r5HlBWPmiSiN1ennkQ0eIbXGPKcDsHwUctMCBRQob9n/
LWNklfSl01uimwPK0g0AcIcFuwKBgQDeIUrQYHp6+Uusz7Kx4Ht1jUiVHB1gd0tk
XU5mrkv5tCof/QtHEq2oKvXFiZ9EHVDeFbSwQWTPfEMtusyQDfcBwdfwuQZmHvww
Rt6hw7Eh7yrVy9NOAQHgcFjdeNoZvPqCIpPEZdSgVHqTU9KRmzYK6fyGQ/kXaIDK
TGWVXdOhowKBgBKOITpJjmMFT7U5G2d4wJ7h3HzSoxaxBq44vZFjte7pbtq2PyGN
doSV4/82zg1jFydsiDui9KD97reRaDDbgBGpb9sNm85FLyXqev0sFfWAnK4iCxWx
EBhFyaQEYoQP5zg3WerKI1OkNsBwzmzeSLcGxAo9/AskIfRZp6P+h279AoGASQqN
fUOcQr+i4KpTSiZUsmzIxy89gbD4e4Iq+5yoou1ZRLeCc9Zyf+/QbSo50r4JD133
0lVOfuOPe4QHK/9Lj6pcBW3x6raZmo5TOsIMhuoMHc0uKGIwacrHjdvla702aoBQ
Mq6BYk8lFzji7roo5SHXxZaoW8gjQWIprRnzMx0CgYAfrt6ao9ZT2dR0wJkzEbg1
2GJ7GfBdMcCnalnTyUkWvNzAjvCPQH0b6BoCcJFrTDJ6t7oOtT23PbxK848XHAD6
NIVvYM1G9NrGxjQR9BAdYShWpMCo85z908e91ASqZQvvGo+TJx7FdpwPK+zZUryx
IGyYG1DC+Q1Ma44s9ntnzA==
-----END PRIVATE KEY-----`)

func newNucleusServerMock() *httptest.Server {
	server := httptest.NewUnstartedServer(
		http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			fmt.Println("URI:", request.RequestURI)
			fmt.Println("Header:", request.Header.Get("Authorization"))

			_, token, _ := request.BasicAuth()
			fmt.Println("Token:", token)

			writer.Write([]byte(`{
				"username": "blah",
				"create_date": 123456789,
				"userinfo": {
					"key": "value"
				}
			}`))
		}),
	)

	server.TLS = new(tls.Config)
	ssl, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		panic(err)
	}
	server.TLS.Certificates = []tls.Certificate{ssl}

	server.StartTLS()

	return server
}

func ExampleAuthenticate() {
	server := newNucleusServerMock()
	defer server.Close()

	err := nucleus.AddCertificate(certificate)
	if err != nil {
		panic(err)
	}

	nucleus.SetAddress(server.URL)

	user, err := nucleus.Authenticate("74cc1c60799e0a786ac7094b532f01b1")
	if err != nil {
		panic(err)
	}

	fmt.Printf("User: %#v\n", user)

	// Output:
	// URI: /api/v1/user
	// Header: Basic Ojc0Y2MxYzYwNzk5ZTBhNzg2YWM3MDk0YjUzMmYwMWIx
	// Token: 74cc1c60799e0a786ac7094b532f01b1
	// User: &nucleus.User{Name:"blah", Info:map[string]interface {}{"key":"value"}, CreateDate:123456789}
}
