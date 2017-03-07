package model

//Authorization Token Model
type Authorization struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"` //bearer or mac
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}
