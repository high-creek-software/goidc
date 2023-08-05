package goidc

type Claims struct {
	Audience          []string `json:"aud"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Exp               int64    `json:"exp"`
	FamilyName        string   `json:"family_name"`
	GivenName         string   `json:"given_name"`
	Locale            string   `json:"locale"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Sub               string   `json:"sub"`
}
