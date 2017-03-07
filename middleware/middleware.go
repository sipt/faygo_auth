package middleware

import (
	"github.com/henrylee2cn/faygo"
	"github.com/sipt/faygo_auth"
	faerror "github.com/sipt/faygo_auth/error"
	"github.com/sipt/faygo_auth/util"
)

//SessionDataKey 对应当前token对应的数据存在session的key值
const SessionDataKey string = "s_data"

//GetTokenMiddleware 获取验证token中间件
func GetTokenMiddleware(provider faygo_auth.AuthProvider) faygo.HandlerFunc {
	return faygo.HandlerFunc(func(ctx *faygo.Context) error {
		bearer := ctx.HeaderParam("Authorization")
		var (
			code      int
			result    interface{}
			resultErr error
		)
		if bearer == "" {
			code = 401
			resultErr = faerror.NewAuthorizeError("Authorization is empty")
		}
		token := util.ParseBearerAuth(bearer)
		if token == "" {
			code = 401
			resultErr = faerror.NewAuthorizeError("Token is empty")
		} else {
			ok, data, err := provider.VerifyToken(token)
			if err != nil {
				code = 403
				resultErr = faerror.NewAuthorizeError(err.Error())
			} else if !ok || data == nil {
				code = 403
				resultErr = faerror.NewAuthorizeError("Invalide Token")
			} else {
				ctx.SetSession(SessionDataKey, data)
				return nil
			}
		}
		result = provider.ErrorHandler(resultErr)
		ctx.JSON(code, result)
		return resultErr
	})
}
