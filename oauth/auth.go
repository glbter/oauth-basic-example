package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/glbter/oauth-basic-lab2/dto"
)

const connection = "Username-Password-Authentication"

type Client struct {
	domain       string
	clientID     string
	clientSecret string
	audience     string
}

type Auth interface {
	ValidateUserToken(token string) (dto.CreateUserResp, error)
	GetTokenWithRefresh(username, password string) (dto.UserTokenResp, error)
	RefreshUserToken(refresh_token string) (dto.TokenResp, error)
	CreateUser(credentials dto.ApiCredentials, user dto.CreateUserReq) (dto.CreateUserResp, error)
	GetToken() (dto.TokenResp, error)
	Logout(returnTo string) string
}

func NewClient(domain, clientID, clientSecret string) Client {
	return Client{
		domain:       domain,
		clientID:     clientID,
		clientSecret: clientSecret,
		audience:     fmt.Sprintf("https://%v/api/v2/", domain),
	}
}

func (c Client) GetToken() (dto.TokenResp, error) {
	payload := strings.NewReader(
		fmt.Sprintf(
			"audience=%v&grant_type=%v&client_id=%v&client_secret=%v",
			c.audience,
			"client_credentials",
			c.clientID,
			c.clientSecret,
		),
	)

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%v/oauth/token", c.domain), payload)
	if err != nil {
		return dto.TokenResp{}, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	var r dto.TokenResp
	if err := decodeResponse(req, http.DefaultClient, &r); err != nil {
		return dto.TokenResp{}, err
	}

	return r, nil
}

func (c Client) CreateUser(credentials dto.ApiCredentials, user dto.CreateUserReq) (dto.CreateUserResp, error) {
	payload := map[string]string{
		"connection":  connection,
		"email":       user.Email,
		"given_name":  user.FirstName,
		"family_name": user.LastName,
		"name":        fmt.Sprintf("%v %v", user.FirstName, user.LastName),
		"password":    user.Password,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return dto.CreateUserResp{}, err
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%v/api/v2/users", c.domain), bytes.NewReader(body))
	if err != nil {
		return dto.CreateUserResp{}, err
	}

	req.Header.Add("Authorization", credentials.Auth)
	req.Header.Add("Content-Type", "application/json")

	var r dto.CreateUserResp
	if err := decodeResponse(req, http.DefaultClient, &r); err != nil {
		return dto.CreateUserResp{}, err
	}

	return r, err
}

func (c Client) GetTokenWithRefresh(username, password string) (dto.UserTokenResp, error) {
	payload := strings.NewReader(
		fmt.Sprintf(
			"audience=%v&grant_type=%v&client_id=%v&client_secret=%v&scope=%v %v&realm=%v&username=%v&password=%v",
			c.audience,
			"http://auth0.com/oauth/grant-type/password-realm",
			c.clientID,
			c.clientSecret,
			"offline_access",
			"openid",
			connection,
			username,
			password,
		),
	)

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%v/oauth/token", c.domain), payload)
	if err != nil {
		return dto.UserTokenResp{}, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	var r dto.UserTokenResp
	if err := decodeResponse(req, http.DefaultClient, &r); err != nil {
		return dto.UserTokenResp{}, err
	}

	return r, nil
}

func (c Client) RefreshUserToken(refresh_token string) (dto.TokenResp, error) {
	payload := strings.NewReader(
		fmt.Sprintf(
			"grant_type=%v&client_id=%v&client_secret=%v&refresh_token=%v",
			"refresh_token",
			c.clientID,
			c.clientSecret,
			refresh_token,
		),
	)

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%v/oauth/token", c.domain), payload)
	if err != nil {
		return dto.TokenResp{}, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	var r dto.TokenResp
	if err := decodeResponse(req, http.DefaultClient, &r); err != nil {
		return dto.TokenResp{}, err
	}

	return r, nil
}

func (c Client) ChangeUserPassword(credentials dto.ApiCredentials, userId, newPassword string) error {
	payload := map[string]string{
		"connection": connection,
		"password":   newPassword,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("https://%v/api/v2/users/%v", c.domain, userId), bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", credentials.Auth)
	req.Header.Add("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	return getErrorFromResponse(res)
}

func getErrorFromResponse(res *http.Response) error {
	if 200 <= res.StatusCode && res.StatusCode < 300 {
		return nil
	}

	bb, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("read response body with status code %v: %w", res.StatusCode, err)
	}

	return fmt.Errorf(string(bb))
}

func decodeResponse(req *http.Request, cl *http.Client, body any) error {
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if err := getErrorFromResponse(res); err != nil {
		return err
	}

	if err := json.NewDecoder(res.Body).Decode(body); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	return nil
}

func (c Client) ValidateUserToken(token string) (dto.CreateUserResp, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%v/userinfo", c.domain), http.NoBody)
	if err != nil {
		return dto.CreateUserResp{}, err
	}

	req.Header.Add("Authorization", token)
	req.Header.Add("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return dto.CreateUserResp{}, err
	}

	defer res.Body.Close()

	var r dto.CreateUserResp
	if err := decodeResponse(req, http.DefaultClient, &r); err != nil {
		return dto.CreateUserResp{}, err
	}

	return r, nil
}

func (c Client) Logout(returnTo string) string {
	return fmt.Sprintf("https://%v/v2/logout?client_id=%v&returnTo=%v", c.domain, c.clientID, returnTo)
}
