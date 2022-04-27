package auth

import (
	"github.com/PKzhilong/oauth2/model"
	"github.com/PKzhilong/oauth2/store"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/golang-jwt/jwt"
	"net/http"
)


type Oauth struct {
	Alg int //算法 1： Hs256(对称加密) 2: RS256(非对称加密)
	Secret string //算法是Hs256 需要给定密钥
	PrivateKey []byte
	PublicKey []byte
	TokenStore model.TokenStore
	ClientStore model.ClientStore
	PasswordAuth server.PasswordAuthorizationHandler

	//初始化完成以后会赋值
	OauthServer *server.Server
	//验证完成会获取token
	TokenInfo oauth2.TokenInfo
}

// SetOauth oauth2 auth server , can user in middleware
func (oh *Oauth) SetOauth() (*server.Server, error) {

	switch oh.Alg {
	case 1:
		return oh.auth2HS256()
		break

	case 2:
		return oh.auth2RS256()
		break
	}

	return oh.auth2HS256()
}

func (oh *Oauth) auth2HS256() (*server.Server, error) {
	manager := manage.NewDefaultManager()

	manager.MustTokenStorage(store.NewDBTokenStore(oh.TokenStore))
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", oh.PrivateKey, jwt.SigningMethodRS256))


	clientStore := store.NewClientStore(oh.ClientStore)
	manager.MapClientStorage(clientStore)

	Oauth2Server := server.NewDefaultServer(manager)
	Oauth2Server.SetAllowGetAccessRequest(true)
	Oauth2Server.SetClientInfoHandler(server.ClientFormHandler)
	Oauth2Server.SetPasswordAuthorizationHandler(oh.PasswordAuth)

	//赋值结构体
	oh.OauthServer = Oauth2Server
	return Oauth2Server, nil
}


func (oh *Oauth) auth2RS256() (*server.Server, error) {

	manager := manage.NewDefaultManager()

	manager.MustTokenStorage(store.NewDBTokenStore(oh.TokenStore))
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", oh.PrivateKey, jwt.SigningMethodRS256))


	clientStore := store.NewClientStore(oh.ClientStore)
	manager.MapClientStorage(clientStore)

	Oauth2Server := server.NewDefaultServer(manager)
	Oauth2Server.SetAllowGetAccessRequest(true)
	Oauth2Server.SetClientInfoHandler(server.ClientFormHandler)
	Oauth2Server.SetPasswordAuthorizationHandler(oh.PasswordAuth)

	oh.OauthServer = Oauth2Server

	return Oauth2Server, nil
}

//HandleAuthorizeRequest 验证请求参数username, password是否获取到用户信息（登陆）
func (oh *Oauth) HandleAuthorizeRequest(r *http.Request) error {

	tokenInfo, err := oh.OauthServer.ValidationBearerToken(r)
	if err != nil {
		return err
	}

	oh.TokenInfo = tokenInfo
	return nil
}
