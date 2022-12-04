package dto

type TokenResp struct {
	Token     string `json:"access_token"`
	Scope     string `json:"scope"`
	ExpiresIn int64  `json:"expires_in"`
	TokenType string `json:"token_type"`
}

type ApiCredentials struct {
	Auth string
}
