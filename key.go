package goidc

type key struct {
	Typ      string `json:"type"`
	KeyID    string `json:"keyId"`
	Key      string `json:"key"`
	ClientID string `json:"clientId"`
	AppID    string `json:"appId"`
}
