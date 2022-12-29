package http

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/glbter/oauth-basic-lab2/dto"
	"github.com/glbter/oauth-basic-lab2/oauth"
)

type Handler struct {
	port       int
	authClient oauth.Auth

	tokenHandler TokenRefresher

	apiToken string
}

func NewHandler(port int, authClient oauth.Auth, tokenHandler TokenRefresher) Handler {
	return Handler{
		port:         port,
		authClient:   authClient,
		tokenHandler: tokenHandler,
	}
}

func (h Handler) base(w http.ResponseWriter, req *http.Request) {
	t, ok := tokenFromRequest(req)
	if t == "" && ok {
		http.ServeFile(w, req, "./http/index.html")
		return
	}

	u, err := UserFromContext(req.Context())
	if err != nil {
		w.WriteHeader(500)
		return
	}

	resp := map[string]string{
		"username": u.Name,
		"logout":   h.authClient.Logout(fmt.Sprintf("http://localhost:%v/", h.port)),
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		w.WriteHeader(500)
		return
	}
}

func (h Handler) login(w http.ResponseWriter, req *http.Request) {
	type user struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}

	var u user
	if err := json.NewDecoder(req.Body).Decode(&u); err != nil {
		w.WriteHeader(500)
		return
	}

	tokens, err := h.authClient.GetTokenWithRefresh(u.Login, u.Password)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	if err := h.addRefreshToken(tokens); err != nil {
		w.WriteHeader(500)
		return
	}

	if err := json.NewEncoder(w).Encode(
		struct {
			Token string `json:"token"`
		}{
			Token: fmt.Sprintf("%v %v", tokens.TokenType, tokens.Token),
		}); err != nil {
		w.WriteHeader(500)
		return
	}
}

func (h Handler) addRefreshToken(token dto.UserTokenResp) error {
	tk, err := h.tokenHandler.ValidateToken(token.Token)
	if err != nil {
		return err
	}

	h.tokenHandler.AddRefreshToken(tk.userID, token.RefreshToken)

	return nil
}

func (h Handler) signUp(w http.ResponseWriter, req *http.Request) {
	u := struct {
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Password  string `json:"password"`
	}{}
	if err := json.NewDecoder(req.Body).Decode(&u); err != nil {
		w.WriteHeader(500)
		return
	}

	apiToken, err := h.getToken()
	if err != nil {
		w.WriteHeader(500)
		return
	}

	if _, err := h.authClient.CreateUser(
		dto.ApiCredentials{
			Auth: apiToken,
		},
		dto.CreateUserReq{
			Email:     u.Email,
			FirstName: u.FirstName,
			LastName:  u.LastName,
			Password:  u.Password,
		},
	); err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
		return
	}
}

func (h Handler) getToken() (string, error) {
	if h.apiToken != "" {
		return h.apiToken, nil
	}

	tk, err := h.authClient.GetToken()
	if err != nil {
		return "", err
	}

	h.apiToken = fmt.Sprintf("%v %v", tk.TokenType, tk.Token)
	return h.apiToken, nil
}

func (h Handler) Run() {
	http.Handle("/api/login", http.HandlerFunc(h.login))
	http.Handle("/", h.tokenHandler.RefreshToken(http.HandlerFunc(h.base)))
	http.Handle("/api/register", http.HandlerFunc(h.signUp))

	http.ListenAndServe(fmt.Sprintf(":%v", h.port), nil)
}
