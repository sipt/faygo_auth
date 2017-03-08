package faygo_auth

//AuthProvider 验证信息提供
type AuthProvider interface {
	//Authorize 验证用户名和密码的正确性
	Authorize(username, password string) (bool, error)

	//VerifyToken 验证Token的有效性
	VerifyToken(token string) (bool, interface{}, error)

	//GetToken 生成Token
	GetToken() (*Authorization, error)

	//RefreshToken 刷新过期token
	RefreshToken(refreshToken string) (*Authorization, error)
}
