package main

import (
	"fmt"

	"github.com/glbter/oauth-basic-lab2/dto"
	"github.com/glbter/oauth-basic-lab2/http"
	"github.com/glbter/oauth-basic-lab2/oauth"
)

const port = 3000

func main() {
	authClient := oauth.NewClient(domain, clientID, clientSecret)
	http.
		NewHandler(port, authClient, http.NewTokenRefresher(authClient, domain)).
		Run()
}

func lab4part2() {
	authClient := oauth.NewClient(domain, clientID, clientSecret)

	tk, err := authClient.GetTokenWithRefresh("john_doe5_hlib@example.com", "auth0-hlib-it-91-pass")
	if err != nil {
		fmt.Println(fmt.Errorf("get token: %w", err))
		return
	}

	fmt.Println(fmt.Sprintf("access token: %v", tk.Token))
	fmt.Println(fmt.Sprintf("refresh token: %v \n", tk.RefreshToken))

	rtk, err := authClient.RefreshUserToken(tk.RefreshToken)
	if err != nil {
		fmt.Println(fmt.Errorf("refresh token: %w", err))
		return
	}

	fmt.Println(fmt.Sprintf("refreshed access token: %v \n", rtk.Token))

	refresher := http.NewTokenRefresher(authClient, domain)
	if _, err := refresher.ValidateToken(tk.Token); err != nil {
		fmt.Println(fmt.Errorf("validate token: %w", err))
		return
	}

	// 	user, err := authClient.ValidateUserToken(fmt.Sprintf("%v %v", tk.TokenType, tk.Token))
	// 	if err != nil {
	// 		fmt.Println(fmt.Errorf("validate token: %w", err))
	// 		return
	// 	}

	// 	fmt.Println(user)
}

func lab3() {
	authClient := oauth.NewClient(domain, clientID, clientSecret)

	tk, err := authClient.GetTokenWithRefresh("john_doe5_hlib@example.com", "auth0-hlib-it-91-pass")
	if err != nil {
		fmt.Println(fmt.Errorf("get token: %w", err))
		return
	}

	fmt.Println(fmt.Sprintf("access token: %v", tk.Token))
	fmt.Println(fmt.Sprintf("refresh token: %v \n", tk.RefreshToken))

	rtk, err := authClient.RefreshUserToken(tk.RefreshToken)
	if err != nil {
		fmt.Println(fmt.Errorf("refresh token: %w", err))
		return
	}

	fmt.Println(fmt.Sprintf("refreshed access token: %v \n", rtk.Token))

	// ---- extended version ----

	mtk, err := authClient.GetToken()
	if err != nil {
		fmt.Println(fmt.Errorf("get token: %w", err))
		return
	}

	if err := authClient.ChangeUserPassword(
		dto.ApiCredentials{Auth: fmt.Sprintf("%v %v", mtk.TokenType, mtk.Token)},
		"auth0|638c6d3706855960064b756e",
		"auth0-hlib-it-91-pass",
	); err != nil {
		fmt.Println(fmt.Errorf("change password: %w", err))
		return
	}

	fmt.Println("finish")
}

func lab2() {
	authClient := oauth.NewClient(domain, clientID, clientSecret)

	tk, err := authClient.GetToken()
	if err != nil {
		fmt.Println(fmt.Errorf("get token: %w", err))
		return
	}

	u, err := authClient.CreateUser(
		dto.ApiCredentials{
			Auth: fmt.Sprintf("%v %v", tk.TokenType, tk.Token),
		},
		dto.CreateUserReq{
			Email:     "john_doe5_hlib@example.com",
			FirstName: "john",
			LastName:  "doe",
			Password:  "auth0-hlib-it-91-pass",
		},
	)
	if err != nil {
		fmt.Println(fmt.Errorf("create token: %w", err))
		return
	}

	_ = u
}
