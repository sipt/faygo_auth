package faygo_auth

import "github.com/henrylee2cn/faygo"

//SessionDataKey 对应当前token对应的数据存在session的key值
const SessionDataKey string = "s_data"

//GetTokenMiddleware 获取验证token中间件
func GetTokenMiddleware(provider AuthProvider) faygo.HandlerFunc {
	return faygo.HandlerFunc(func(ctx *faygo.Context) error {
		bearer := ctx.HeaderParam("Authorization")
		var (
			code      int
			result    interface{}
			resultErr error
		)
		if bearer == "" {
			code = 401
			resultErr = NewAuthorizeError("Authorization is empty")
		}
		token := ParseBearerAuth(bearer)
		if token == "" {
			code = 401
			resultErr = NewAuthorizeError("Token is empty")
		} else {
			ok, data, err := provider.VerifyToken(token)
			if err != nil {
				code = 403
				resultErr = NewAuthorizeError(err.Error())
			} else if !ok || data == nil {
				code = 403
				resultErr = NewAuthorizeError("Invalide Token")
			} else {
				ctx.SetSession(SessionDataKey, data)
				return nil
			}
		}
		result = ErrorHandler(resultErr)
		ctx.JSON(code, result)
		return resultErr
	})
}
