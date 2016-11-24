package nucleus

import (
	"fmt"
	"os"
	"testing"
)

func TestAuthenticateRemote(t *testing.T) {
	err := AddCertificate([]byte(os.Getenv("CERTIFICATE")))
	if err != nil {
		panic(err)
	}

	SetAddress(os.Getenv("ADDRESS"))

	user, err := Authenticate(os.Getenv("TOKEN"))
	if err != nil {
		panic(err)
	}

	fmt.Printf("User: %#v\n", user)
}
