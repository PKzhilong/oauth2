package model

import (
	"context"
	"github.com/go-oauth2/oauth2/v4"
)

type (

	ClientStore interface {
		// according to the ID for the client information
		GetByID(ctx context.Context, id string) (Client, error)
	}

	// TokenStore token model to update or create
	TokenStore interface {
		CreateOrUpdateCode(context.Context, oauth2.TokenInfo) error
		CreateOrUpdateToken(context.Context, oauth2.TokenInfo) error

		DeletedByCode(context.Context, string) error
		DeletedByAccess(context.Context, string) error
		DeletedByRefresh(context.Context, string) error

		GetByCode(context.Context, string) (oauth2.TokenInfo, error)
		GetByAccess(context.Context, string) (oauth2.TokenInfo, error)
		GetByRefresh(context.Context, string) (oauth2.TokenInfo, error)
	}
)
