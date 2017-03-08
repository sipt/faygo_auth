package faygo_auth

type baseError struct {
	msg string
}

func (b *baseError) Error() string {
	return b.msg
}

//AuthorizeError 用户名和密码验证失败
type AuthorizeError struct {
	baseError
}

func NewAuthorizeError(msg string) *AuthorizeError {
	return &AuthorizeError{
		baseError: baseError{
			msg: msg,
		},
	}
}

//CreateTokenError 生成Token失败
type CreateTokenError struct {
	baseError
}

func NewCreateTokenError(msg string) *CreateTokenError {
	return &CreateTokenError{
		baseError: baseError{
			msg: msg,
		},
	}
}

//InvalidTokenError Token无效
type InvalidTokenError struct {
	baseError
}

func NewInvalidTokenError(msg string) *InvalidTokenError {
	return &InvalidTokenError{
		baseError: baseError{
			msg: msg,
		},
	}
}

//InvalidRefreshTokenError RefreshToken无效
type InvalidRefreshTokenError struct {
	baseError
}

func NewInvalidRefreshTokenError(msg string) *InvalidRefreshTokenError {
	return &InvalidRefreshTokenError{
		baseError: baseError{
			msg: msg,
		},
	}
}

//RefreshTokenError RefreshToken无效
type RefreshTokenError struct {
	baseError
}

func NewRefreshTokenError(msg string) *RefreshTokenError {
	return &RefreshTokenError{
		baseError: baseError{
			msg: msg,
		},
	}
}
