package faygo_auth

import (
	"github.com/henrylee2cn/faygo"
)

// AuthRoute register router in a tree style.
func AuthRoute(frame *faygo.Framework, provider AuthProvider) {
	a := NewAuthorizationController(provider)
	frame.Route(
		frame.NewNamedAPI("Authorize", "GET", "/authorize", a.Authorize),
		frame.NewNamedAPI("refresh_token", "GET", "/refresh_token", a.RefreshToken),
	)
}
