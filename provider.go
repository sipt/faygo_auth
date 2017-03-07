package faygo_auth

import "github.com/sipt/faygo_auth/model"

//AuthProvider 验证信息提供
type AuthProvider interface {
	//Authorize 验证用户名和密码的正确性
	Authorize(username, password string) (bool, error)

	//VerifyToken 验证Token的有效性
	VerifyToken(token string) (bool, interface{}, error)

	//GetToken 生成Token
	GetToken() (*model.Authorization, error)

	//RefreshToken 刷新过期token
	RefreshToken(refreshToken string) (*model.Authorization, error)

	//ErrorHandler 错误处理，以及错误返回
	ErrorHandler(err error) interface{}

	//DataHandler 数据捕获，返回自定义格式
	DataHandler(authorization *model.Authorization) interface{}
}
