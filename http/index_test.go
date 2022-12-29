package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/glbter/oauth-basic-lab2/dto"
	oauth "github.com/glbter/oauth-basic-lab2/oauth/mocks"
)

func TestHandler_Base(t *testing.T) {
	t.Run("unit_ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		auth := oauth.NewMockAuth(ctrl)

		auth.EXPECT().
			ValidateUserToken("token").
			Return(dto.CreateUserResp{Name: "name"}, nil)

		auth.EXPECT().
			Logout("http://localhost:0/").
			Return("/logout")

		r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer token")

		recorder := httptest.NewRecorder()
		http.HandlerFunc(Handler{authClient: auth}.base).ServeHTTP(recorder, r)

		require.Equal(t, http.StatusOK, recorder.Code)
		require.JSONEq(t, `{"logout":"/logout","username":"name"}`, recorder.Body.String())
	})
}
