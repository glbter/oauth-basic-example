package dto

import "time"

type CreateUserReq struct {
	Email     string
	FirstName string
	LastName  string
	Password  string
}

type CreateUserResp struct {
	Email      string         `json:"email"`
	FirstName  string         `json:"given_name"`
	LastName   string         `json:"family_name"`
	Name       string         `json:"name"`
	UserID     string         `json:"user_id"`
	Identities []UserIdentity `json:"identities"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

type UserIdentity struct {
	Connection string `json:"connection"`
	UserID     string `json:"user_id"`
	Provider   string `json:"provider"`
}

type UserTokenResp struct {
	Token        string `json:"access_token"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
}

type UserWithIDResp struct {
	Token        string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}
