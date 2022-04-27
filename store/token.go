package store

import (
	"context"
	"github.com/PKzhilong/oauth2/model"

	"github.com/go-oauth2/oauth2/v4"
)

// NewDBTokenStore create a token store instance based on file
func NewDBTokenStore(DB model.TokenStore) (oauth2.TokenStore, error) {
	return &TokenStore{db: DB}, nil
}

// TokenStore token storage based on db(https://github.com/tidwall/buntdb)
type TokenStore struct {
	db model.TokenStore
}

// Create create and store the new token information
func (ts *TokenStore) Create(ctx context.Context, info oauth2.TokenInfo) error {

	if code := info.GetCode(); code != "" {
		return ts.db.CreateOrUpdateCode(ctx, info)
	}

	//...todo 这里token，refresh_token过期时间需要后面在做处理比较复杂
	return  ts.db.CreateOrUpdateToken(ctx, info)
}

// RemoveByCode use the authorization code to delete the token information
func (ts *TokenStore) RemoveByCode(ctx context.Context, code string) error {
	return ts.db.DeletedByCode(ctx, code)
}

// RemoveByAccess use the access token to delete the token information
func (ts *TokenStore) RemoveByAccess(ctx context.Context, access string) error {
	return ts.db.DeletedByAccess(ctx, access)
}

// RemoveByRefresh use the refresh token to delete the token information
func (ts *TokenStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	return ts.db.DeletedByRefresh(ctx, refresh)
}


// GetByCode use the authorization code for token information data
func (ts *TokenStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	return ts.db.GetByCode(ctx, code)
}

// GetByAccess use the access token for token information data
func (ts *TokenStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	return ts.db.GetByAccess(ctx, access)

}

// GetByRefresh use the refresh token for token information data
func (ts *TokenStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	return ts.db.GetByRefresh(ctx, refresh)
}
