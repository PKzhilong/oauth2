package store

import (
	"context"
	"errors"
	"github.com/PKzhilong/oauth2/model"
	"sync"

	"github.com/go-oauth2/oauth2/v4"
)

// NewClientStore create client store
func NewClientStore(dbs model.ClientStore) *ClientStore {
	return &ClientStore{
		db: dbs,
	}
}

// ClientStore client information store
type ClientStore struct {
	sync.RWMutex
	db model.ClientStore
}

// GetByID according to the ID for the client information
func (cs *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	cs.RLock()
	defer cs.RUnlock()
	//查oauth_client 表获取相关client参数，并返回
	cInfo, err := cs.db.GetByID(ctx, id)
	if err == nil {
		return &cInfo, nil
	}
	return nil, errors.New("not found")
}
