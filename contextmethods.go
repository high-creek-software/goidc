package goidc

import (
	"context"
	"net/http"
)

type ctxKey int

var authResponseKey = ctxKey(22)
var claimsResponseKey = ctxKey(24)

func SetAuthResponse(ar AuthResponse, r *http.Request) {
	ctx := r.Context()
	ctx = context.WithValue(ctx, authResponseKey, ar)
	*r = *(r.WithContext(ctx))
}

func AuthResponseFromContext(r *http.Request) (AuthResponse, bool) {
	ar, ok := r.Context().Value(authResponseKey).(AuthResponse)
	return ar, ok
}

func SetClaims(c Claims, r *http.Request) {
	ctx := r.Context()
	ctx = context.WithValue(ctx, claimsResponseKey, c)
	*r = *(r.WithContext(ctx))
}

func ClaimsFromContext(r *http.Request) (Claims, bool) {
	c, ok := r.Context().Value(claimsResponseKey).(Claims)
	return c, ok
}
