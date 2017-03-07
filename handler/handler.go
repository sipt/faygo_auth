package handler

import (
	"github.com/henrylee2cn/faygo"
	"github.com/sipt/faygo_auth"
	faerror "github.com/sipt/faygo_auth/error"
	"github.com/sipt/faygo_auth/util"
)

//AuthorizationController 验证用API接口
type AuthorizationController struct {
	Authorize    faygo.Handler
	RefreshToken faygo.Handler
}

//NewAuthorizationController 创建验证用API接口
func NewAuthorizationController(provider faygo_auth.AuthProvider) *AuthorizationController {
	return &AuthorizationController{
		Authorize: faygo.WrapDoc(
			faygo.HandlerFunc(func(ctx *faygo.Context) error {
				var (
					code      int
					result    interface{}
					resultErr error
				)
				auth := ctx.HeaderParam("Authorization")
				username, password, ok := util.ParseBasicAuth(auth)
				if ok {
					ok, err := provider.Authorize(username, password)
					if err != nil {
						code = 403
						resultErr = faerror.NewAuthorizeError(err.Error())
					} else if !ok {
						code = 403
						resultErr = faerror.NewAuthorizeError("Authorize Failed")
					} else {
						a, err := provider.GetToken()
						if err != nil {
							code = 500
							resultErr = faerror.NewAuthorizeError(err.Error())
						} else if a == nil {
							code = 500
							resultErr = faerror.NewCreateTokenError("Create Token Failed")
						} else {
							code = 200
							result = a
						}
					}
				} else {
					code = 401
					resultErr = faerror.NewAuthorizeError("Unauthorization")
				}
				if result == nil {
					result = provider.ErrorHandler(resultErr)
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
					resultErr = faerror.NewRefreshTokenError(err.Error())
				} else if a == nil {
					code = 500
					resultErr = faerror.NewRefreshTokenError("Refresh Token Failed")
				} else {
					code = 200
					result = a
				}
				if result == nil {
					result = provider.ErrorHandler(resultErr)
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
