package goidc

type Client struct {
	issuer string
	keyRefreshDuration time.Duration
}

func NewClient(issuer string, keyRefreshDuration time.Duration) *Client {
	c := &Client{issuer: issuer, keyRefreshDuration: keyRefreshDuration}
	c.init()

	return c
}

func (c *Client) init() {
	
}
