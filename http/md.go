package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/glbter/oauth-basic-lab2/dto"
	"github.com/glbter/oauth-basic-lab2/oauth"

	"github.com/golang-jwt/jwt/v4"
)

const (
	UserContext     = "user"
	UserCodeContext = "user-auth-code"
)

type TokenRefresher struct {
	// is used for demonstration purpose, can't be used in prod, as it isn't concurent safe
	refreshTokens map[string]string

	domain string
	ssoURL string

	authClient oauth.Auth
}

func NewTokenRefresher(authClient oauth.Auth, domain, ssoURL string) TokenRefresher {
	return TokenRefresher{
		refreshTokens: make(map[string]string, 0),
		authClient:    authClient,
		domain:        domain,
		ssoURL:        ssoURL,
	}
}

func (t TokenRefresher) RefreshToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := codeFromRequest(r)
		// fmt.Println(r.URL.RequestURI())
		if ok {
			// fmt.Println("got code")

			next.ServeHTTP(w, r)
			return
		}

		tk, ok := tokenFromRequest(r)
		if tk == "" && ok {
			// fmt.Println("redirect")
			// http.Redirect(w, r, t.ssoURL, http.StatusSeeOther)

			next.ServeHTTP(w, r)
			return
		}

		if !ok {
			w.WriteHeader(400)
			return
		}

		u, err := t.authClient.ValidateUserToken(fmt.Sprintf("Bearer %v", tk))
		if err != nil {
			w.WriteHeader(401)
			return
		}

		userToken, err := t.ValidateToken(tk)
		if err != nil {
			w.WriteHeader(401)
			return
		}

		if userToken.expiresAt.Sub(time.Now()).Hours() < 25 {
			tr, err := t.authClient.RefreshUserToken(t.GetRefreshToken(userToken.userID))
			if err != nil {
				fmt.Println(err)
				w.WriteHeader(500)
				return
			}

			w.Header().Add("Authorization", fmt.Sprintf("%v %v", tr.TokenType, tr.Token))
		}

		next.ServeHTTP(w, r.WithContext(ContextWithUser(r.Context(), u)))
	})
}

func ContextWithUser(ctx context.Context, u dto.CreateUserResp) context.Context {
	return context.WithValue(ctx, UserContext, u)
}

func UserFromContext(ctx context.Context) (dto.CreateUserResp, error) {
	u, ok := ctx.Value(UserContext).(dto.CreateUserResp)
	if !ok {
		return dto.CreateUserResp{}, fmt.Errorf("no user in context")
	}

	return u, nil
}

// func ContextWithAuthCode(ctx context.Context, code string) context.Context {
// 	return context.WithValue(ctx, UserCodeContext, code)
// }

// func AuthCodeFromContext(ctx context.Context) (string, error) {
// 	u, ok := ctx.Value(UserContext).(string)
// 	if !ok {
// 		return "", fmt.Errorf("no auth code in context")
// 	}

// 	return u, nil
// }

func (t TokenRefresher) AddRefreshToken(userID, token string) {
	if _, ok := t.refreshTokens[userID]; !ok {
		t.refreshTokens[userID] = token
	}
}

func (t TokenRefresher) GetRefreshToken(userID string) string {
	return t.refreshTokens[userID]
}

type ParsedToken struct {
	userID    string
	expiresAt time.Time
}

func (t TokenRefresher) ValidateToken(token string) (ParsedToken, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%v/pem", t.domain), http.NoBody)
	if err != nil {
		return ParsedToken{}, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return ParsedToken{}, err
	}

	defer res.Body.Close()

	key, err := io.ReadAll(res.Body)
	if err != nil {
		return ParsedToken{}, err
	}

	pem, err := jwt.ParseRSAPublicKeyFromPEM(key)
	if err != nil {
		return ParsedToken{}, err
	}

	tk, err := jwt.NewParser().ParseWithClaims(token, &jwt.RegisteredClaims{}, func(tk *jwt.Token) (interface{}, error) {
		return pem, nil
	})

	// tk, _, err := jwt.NewParser().ParseUnverified(token, &jwt.RegisteredClaims{})

	if err != nil {
		return ParsedToken{}, fmt.Errorf("parse token: %w", err)
	}

	if !tk.Valid {
		return ParsedToken{}, fmt.Errorf("not valid token")
	}

	cl, ok := tk.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return ParsedToken{}, fmt.Errorf("parse claims: %w", err)
	}

	return ParsedToken{expiresAt: cl.ExpiresAt.Time, userID: cl.Subject}, nil
}

func tokenFromRequest(r *http.Request) (string, bool) {
	t := r.Header.Get("Authorization")
	if t == "" {
		return "", true
	}

	splt := strings.Split(t, "Bearer ")
	if len(splt) != 2 {
		return "", false
	}

	return splt[1], true
}

func codeFromRequest(r *http.Request) (string, bool) {
	if code := r.URL.Query().Get("code"); code != "" {
		return code, true
	}

	return "", false
}

func writeErrorMessage(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(
		struct {
			Message string
			Error   int
		}{
			Message: msg,
			Error:   code,
		})

	return
}
