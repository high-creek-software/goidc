package goidc

type Endpoints interface {
	Authorize() string
	Keys() string
	Token() string
}

type ZitadelEndpoints struct {
}

func (z ZitadelEndpoints) Authorize() string {
	return "/oauth/v2/authorize"
}

func (z ZitadelEndpoints) Keys() string {
	return "/oauth/v2/keys"
}

func (z ZitadelEndpoints) Token() string {
	return "/oauth/v2/token"
}
