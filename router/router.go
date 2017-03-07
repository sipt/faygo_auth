package router

import (
	"github.com/henrylee2cn/faygo"
	"github.com/sipt/faygo_auth"
	"github.com/sipt/faygo_auth/handler"
)

// AuthRoute register router in a tree style.
func AuthRoute(frame *faygo.Framework, provider faygo_auth.AuthProvider) {
	a := handler.NewAuthorizationController(provider)
	frame.Route(
		frame.NewNamedAPI("Authorize", "GET", "/authorize", a.Authorize),
		frame.NewNamedAPI("refresh_token", "GET", "/refresh_token", a.RefreshToken),
	)
}
