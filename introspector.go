package goidc

type Introspector interface {
	Introspect(token string) (bool, error)
}
