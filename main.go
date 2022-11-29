package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func main() {
	tk, err := getToken(
		DOMAIN,
		fmt.Sprintf("https://%v/api/v2/", DOMAIN),
		CLIENT_ID,
		CLIENT_SECRET,
	)
	// tk, err := getToken(
	// 	EXAMPLE_DOMAIN,
	// 	fmt.Sprintf("https://%v/api/v2/", EXAMPLE_DOMAIN),
	// 	EXAMPLE_CLIENT_ID,
	// 	EXAMPLE_CLIENT_SECRET,
	// )
	if err != nil {
		fmt.Println(fmt.Errorf("get token: %w", err))
		return
	}

	fmt.Println(fmt.Sprintf("%v %v", tk.TokenType, tk.Token))

	u, err := createUser(
		apiCredentials{
			auth:   fmt.Sprintf("%v %v", tk.TokenType, tk.Token),
			domain: DOMAIN,
		},
		createUserReq{
			email:     "john_doe1_hlib@example.com",
			firstName: "john",
			lastName:  "doe",
			password:  "auth0-hlib-it-91-pass",
		},
	)

	if err != nil {
		fmt.Println(fmt.Errorf("create token: %w", err))
		return
	}

	fmt.Println(u)
}

type tokenResp struct {
	Token     string `json:"access_token"`
	Scope     string `json:"scope"`
	ExpiresIn int64  `json:"expires_in"`
	TokenType string `json:"token_type"`
}

func getToken(
	domain, audience, clientID, clientSecret string,
) (tokenResp, error) {
	payload := strings.NewReader(
		fmt.Sprintf(
			"audience=%v&grant_type=%v&client_id=%v&client_secret=%v",
			audience,
			"client_credentials",
			clientID,
			clientSecret,
		),
	)

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%v/oauth/token", domain), payload)
	if err != nil {
		return tokenResp{}, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return tokenResp{}, err
	}
	defer res.Body.Close()

	if !(200 <= res.StatusCode && res.StatusCode < 300) {
		bb, err := io.ReadAll(res.Body)
		if err != nil {
			return tokenResp{}, err
		}
		return tokenResp{}, fmt.Errorf(string(bb))
	}

	var r tokenResp
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		return tokenResp{}, err
	}

	return r, nil
}

type createUserReq struct {
	email     string
	firstName string
	lastName  string
	password  string
}

type apiCredentials struct {
	auth   string
	domain string
}

type createUserResp struct {
	Email      string         `json:"email"`
	FirstName  string         `json:"given_name"`
	LastName   string         `json:"family_name"`
	Name       string         `json:"name"`
	UserID     string         `json:"user_id"`
	Identities []userIdentity `json:"identities"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

type userIdentity struct {
	Connection string `json:"connection"`
	UserID     string `json:"user_id"`
	Provider   string `json:"provider"`
}

func createUser(credentials apiCredentials, user createUserReq) (createUserResp, error) {
	payload := map[string]string{
		"connection":  "Username-Password-Authentication",
		"email":       user.email,
		"given_name":  user.firstName,
		"family_name": user.lastName,
		"name":        fmt.Sprintf("%v %v", user.firstName, user.lastName),
		"password":    user.password,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return createUserResp{}, err
	}

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%v/api/v2/users", credentials.domain), bytes.NewReader(body))
	if err != nil {
		return createUserResp{}, err
	}

	req.Header.Add("Authorization", credentials.auth)
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return createUserResp{}, err
	}

	defer res.Body.Close()

	if !(200 <= res.StatusCode && res.StatusCode < 300) {
		bb, err := io.ReadAll(res.Body)
		if err != nil {
			return createUserResp{}, err
		}
		return createUserResp{}, fmt.Errorf(string(bb))
	}

	var r createUserResp
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		return createUserResp{}, err
	}

	return r, err
}
