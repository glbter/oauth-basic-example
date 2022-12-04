package main

import (
	"fmt"

	"github.com/glbter/oauth-basic-lab2/dto"
	"github.com/glbter/oauth-basic-lab2/oauth"
)

func main() {
	lab3()
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
		"auth0|63890ef012655f46ea73904b",
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
