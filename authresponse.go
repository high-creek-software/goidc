package goidc

type AuthResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	State       string `json:"state"`
}

func (ar AuthResponse) String() string {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("Access Token -> %s \n", ar.AccessToken))
	sb.WriteString(fmt.Sprintf("Token Type -> %s \n", ar.TokenType))
	sb.WriteString(fmt.Sprintf("Expires In -> %d \n", ar.ExpiresIn))
	sb.WriteString(fmt.Sprintf("State -> %s \n", ar.State))
	sb.WriteString(fmt.Sprintf("ID Token -> %s \n", ar.IDToken))

	return sb.String()
}
