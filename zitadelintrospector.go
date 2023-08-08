package goidc

import (
	"context"
	"github.com/carlmjohnson/requests"
	"github.com/go-jose/go-jose/v3/json"
	"net/url"
	"os"
)

type ZitadelIntrospector struct {
	issuer    string
	endpoints Endpoints
	key       key
}

func NewZitadelIntrospectorWithData(issuer string, endpoints Endpoints, data []byte) (Introspector, error) {
	var key key
	err := json.Unmarshal(data, &key)
	if err != nil {
		return nil, err
	}
	return &ZitadelIntrospector{issuer: issuer, endpoints: endpoints, key: key}, nil
}

func NewZitadelIntrospectorFromFile(issuer, path string, endpoints Endpoints) (Introspector, error) {

	in, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	var key key
	err = json.NewDecoder(in).Decode(&key)
	if err != nil {
		return nil, err
	}

	return &ZitadelIntrospector{issuer: issuer, endpoints: endpoints, key: key}, nil
}

func (zi *ZitadelIntrospector) Introspect(token string) (bool, error) {
	// Get jwt from the key data
	jot, err := generateJWT(zi.key, zi.issuer)
	if err != nil {
		return false, err
	}

	// Make the request to the endpoint
	data := url.Values{}
	data.Set("client_assertion", jot)
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("token", token)

	var ir IntrospectionResult
	err = requests.URL(zi.issuer).Path(zi.endpoints.Introspect()).
		Post().
		BodyForm(data).
		ToJSON(&ir).
		Fetch(context.Background())

	if err != nil {
		return false, err
	}

	return ir.Active, nil
}

type IntrospectionResult struct {
	Active bool `json:"active"`
}
