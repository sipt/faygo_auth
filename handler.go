package faygo_auth

import (
	"github.com/henrylee2cn/faygo"
)

//AuthorizationController 验证用API接口
type AuthorizationController struct {
	Authorize    faygo.Handler
	RefreshToken faygo.Handler
}

//ErrorHandler default error handler
var ErrorHandler = func(ctx *faygo.Context, status int, err error) {
	ctx.JSON(status, `{"error":{"msg":"`+err.Error()+`"}}`)
}

//DataHandler default data handler
var DataHandler = func(ctx *faygo.Context, status int, data interface{}) {
	ctx.JSON(status, data)
}

//NewAuthorizationController 创建验证用API接口
func NewAuthorizationController(provider AuthProvider) *AuthorizationController {
	return &AuthorizationController{
		Authorize: faygo.WrapDoc(
			faygo.HandlerFunc(func(ctx *faygo.Context) error {
				var (
					code      int
					result    interface{}
					resultErr error
				)
				auth := ctx.HeaderParam("Authorization")
				username, password, ok := ParseBasicAuth(auth)
				if ok {
					ok, err := provider.Authorize(username, password)
					if err != nil {
						code = 403
						resultErr = NewAuthorizeError(err.Error())
					} else if !ok {
						code = 403
						resultErr = NewAuthorizeError("Authorize Failed")
					} else {
						a, err := provider.GetToken()
						if err != nil {
							code = 500
							resultErr = NewAuthorizeError(err.Error())
						} else if a == nil {
							code = 500
							resultErr = NewCreateTokenError("Create Token Failed")
						} else {
							code = 200
							result = a
						}
					}
				} else {
					code = 401
					resultErr = NewAuthorizeError("Unauthorization")
				}
				if result == nil {
					result = ErrorHandler(resultErr)
				}
				ctx.JSON(code, result)
				return resultErr
			}),
			"Authorize",
			"返回token对象",
			// 定义参数
			faygo.ParamInfo{
				Name:     "Authorization",
				In:       "header",
				Required: true,
				Model:    string("Basic base64(u:p)"),
				Desc:     "Basic base64(username:password)",
			},
		),
		RefreshToken: faygo.WrapDoc(
			faygo.HandlerFunc(func(ctx *faygo.Context) error {
				var (
					code      int
					resultErr error
					result    interface{}
				)
				a, err := provider.RefreshToken(ctx.Param("refresh_token"))
				if err != nil {
					code = 500
					resultErr = NewRefreshTokenError(err.Error())
				} else if a == nil {
					code = 500
					resultErr = NewRefreshTokenError("Refresh Token Failed")
				} else {
					code = 200
					result = a
				}
				if result == nil {
					result = ErrorHandler(resultErr)
				}
				ctx.JSON(code, result)
				return resultErr
			}),
			"RefreshToken",
			"刷新过期token",
			// 定义参数
			faygo.ParamInfo{
				Name:     "refresh_token",
				In:       "query",
				Required: true,
				Model:    string("refresh_token"),
				Desc:     "RefreshToken",
			},
		),
	}
}
