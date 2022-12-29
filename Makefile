mockgen:
 mockgen -package mocks \
 -destination ./oauth/mocks/mock.go \
 github.com/glbter/oauth-basic-lab2/oauth \
 Auth
.PHONY: mockgen

 mockgen -package mocks -destination ./oauth/mocks/mock.go  github.com/glbter/oauth-basic-lab2/oauth  Auth