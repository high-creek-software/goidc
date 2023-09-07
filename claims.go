package goidc

type Claims struct {
	Audience          []string                     `json:"aud"`
	AuthTime          int                          `json:"auth_time"`
	Email             string                       `json:"email"`
	EmailVerified     bool                         `json:"email_verified"`
	Exp               int64                        `json:"exp"`
	FamilyName        string                       `json:"family_name"`
	GivenName         string                       `json:"given_name"`
	Name              string                       `json:"name"`
	PreferredUsername string                       `json:"preferred_username"`
	Nickname          string                       `json:"nickname"`
	Locale            string                       `json:"locale"`
	Sub               string                       `json:"sub"`
	Picture           string                       `json:"picture"`
	Roles             map[string]map[string]string `json:"urn:zitadel:iam:org:project:roles"` // This probably isn't going to work across providers, but I'm only working with zitadel on this right now
}

func (c Claims) GetRoleNames() []string {
	var keys []string
	for k, _ := range c.Roles {
		keys = append(keys, k)
	}
	return keys
}
